/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * base_message_channel.c
 *
 *  Created on: Apr 14, 2011
 *      Author: daveds
 */

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#include <common/platform.h>
#include <common/atomic.h>
#include <common/hash.h>
#include <common/debug.h>
#include <libservalctrl/task.h>
#include "message_channel_internal.h"
#include "message_channel_base.h"

#if defined(ENABLE_USERMODE)
#include <libserval/serval.h>
#endif

static int make_async(int fd)
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL, 0)) < 0) {
        LOG_ERR("F_GETFL error on fd %d (%s)", fd, strerror(errno));
        return -1;
    }

    flags |= O_NONBLOCK;

    if (fcntl(fd, F_SETFL, flags) < 0) {
        LOG_ERR("F_SETFL error on fd %d (%s)", fd, strerror(errno));
        return -1;
    }
    return 0;
}

static int set_reuse_ok(int soc)
{
    int option = 1;
    
    if (setsockopt(soc, SOL_SOCKET, SO_REUSEADDR, 
                   &option, sizeof(option)) < 0) {
        LOG_ERR("proxy setsockopt error");
        return -1;
    }
    return 0;
}

int message_channel_base_equalfn(const message_channel_t *channel, 
                                 const void *_key)
{
    channel_key_t *key = (channel_key_t *)_key;
    const message_channel_base_t *base = (const message_channel_base_t *)channel;

    if (key->type != channel->type ||
        //key->sock_type != base->sock_type ||
        key->protocol != base->protocol)
        return 0;
    
    if (key->peer && key->peer_len > 0) {
        if (key->peer_len != base->peer_len)
            return 0;

        if (memcmp(key->peer, &base->peer, key->peer_len) != 0)
            return 0;
    }
    if (key->local && key->local_len > 0) {
        if (key->local_len != base->local_len)
            return 0;

        if (memcmp(key->local, &base->local, key->local_len) != 0)
            return 0;
    }
    return 1;
}

int message_channel_base_fillkey(const message_channel_t *channel, void *_key)
{
    message_channel_base_t *base = (message_channel_base_t *)channel;
    channel_key_t *key = (channel_key_t *)_key;

    key->type = channel->type;
    key->flags = channel->flags;
    key->local = &base->local.sa;
    key->local_len = base->local_len;
    key->peer = &base->peer.sa;
    key->peer_len = base->peer_len;
    key->sock_type = base->sock_type;
    key->protocol = base->protocol;

    return 0;
}

int message_channel_base_initialize(message_channel_t *channel)
{
    message_channel_base_t *base = (message_channel_base_t *)channel;
    int err = 0;

    assert(channel);
 
    LOG_DBG("Initializing %s channel family=%d\n", 
            channel->name, base->local.sa.sa_family);

    if (channel->state != CHANNEL_CREATED) {
        LOG_ERR("Channel in bad state\n");
        return -1;
    }
    
    base->buffer = malloc(base->buffer_len);

    if (!base->buffer)
        return -1;

    memset(base->buffer, 0, base->buffer_len);
    base->native_socket = 1;

    base->sock = socket(base->local.sa.sa_family, 
                        base->sock_type, base->protocol);

    if (base->sock == -1) {
        switch (errno) {
        case EAFNOSUPPORT:
        case EPROTONOSUPPORT:
#if defined(ENABLE_USERMODE)
            /* Try libserval */
            LOG_DBG("%s is usermode channel\n",
                    channel->name);

            base->sock = socket_sv(base->local.sa.sa_family,
                                   base->sock_type, base->protocol);
            
            if (base->sock == -1) {
                LOG_ERR("Could not create socket: %s\n",
                        strerror_sv(errno));
                err = -1;
                goto sock_error;
            }
            base->native_socket = 0;
#else
            LOG_ERR("%s %s sock_type=%d protocol=%d\n",
                    channel->name, strerror(errno), 
                    base->sock_type, base->protocol);
            goto sock_error;
#endif /* ENABLE_USERMODE */
            break;
        default:
            LOG_ERR("%s Could not create socket (native): %s\n",
                    channel->name, strerror(errno));
            err = -1;
            goto sock_error;
        }
    } 
    
    if (base->sock == -1) {
        LOG_ERR("%s\n", strerror(errno));
        err = -1;
        goto sock_error;
    }
    
    err = -1;
    
    if (base->local_len > 0) {
        if (base->native_socket) {
            err = bind(base->sock, &base->local.sa, base->local_len);
        } 
#if defined(ENABLE_USERMODE)
        else {
            err = bind_sv(base->sock, &base->local.sa, base->local_len);
        }
#endif
    }
    
    if (err == -1) {
        fprintf(stderr, "Error binding socket: %s\n", strerror(errno));
        goto bind_error;
    }

    set_reuse_ok(base->sock);
    make_async(base->sock);
    
    channel->state = CHANNEL_INITIALIZED;
    base->running = 1;

out:
    return err;
bind_error:
    if (base->native_socket)
        close(base->sock);
#if defined(ENABLE_USERMODE)
    else
        close_sv(base->sock);
#endif

    base->sock = -1;
sock_error:
    free(base->buffer);
    base->buffer = NULL;
    goto out;
}

/* 
   Finalize does not need lock protection since it should only happend
   when refcount has reached zero.
 */
void message_channel_base_finalize(message_channel_t *channel)
{
    message_channel_base_t *base = (message_channel_base_t *)channel;

    assert(channel);

    LOG_DBG("%s finalizing\n", base->channel.name);

    if (channel->state == CHANNEL_RUNNING)
        base->channel.ops->stop(channel);

    if (base->sock > 0) {
        if (base->native_socket)
            close(base->sock);
#if defined(ENABLE_USERMODE)
        else
            close_sv(base->sock);
#endif
        base->sock = -1;
    }
    
    if (base->buffer) {
        LOG_DBG("%s free buffer\n", channel->name);
        free(base->buffer);
    }

    channel->state = CHANNEL_CREATED;
}

static void message_channel_base_task(void *channel)
{
    message_channel_base_t *base = (message_channel_base_t *)channel;
    channel_addr_t peer;
    socklen_t addrlen = sizeof(peer);
    ssize_t ret = -1;

    while (base->running) {
        /* LOG_DBG("%s receive task running\n", base->channel.name); */

        if (base->native_socket) {
            ret = recvfrom(base->sock, base->buffer,
                           base->buffer_len, 0,
                           &peer.sa, &addrlen);
        } 
#if defined(ENABLE_USERMODE)
        else {
            ret = recvfrom_sv(base->sock, base->buffer,
                              base->buffer_len, 0,
                              &peer.sa, &addrlen);
        }
#endif
        if (ret == -1) {
            if (errno == EAGAIN || 
                errno == EWOULDBLOCK) {
                
                ret = task_block(base->sock, FD_READ);

                if (ret == 0)
                    continue;
                else if (ret == -1)
                    base->running = 0;
            } else {
                LOG_ERR("%s recv error: %s\n",
                        base->channel.name, strerror(errno));
                base->running = 0;
            }
        } else if (ret == 0) {
            LOG_DBG("%s other end closed\n",
                    base->channel.name);
            base->running = 0;
        } else {
            /* LOG_DBG("%s Received a message len=%zd\n", 
               base->channel.name, ret); */
            base->channel.ops->recv(&base->channel, base->buffer, (size_t)ret, 
                                    &peer.sa, addrlen);
        }
    }
    LOG_DBG("%s task exits\n", base->channel.name);
    base->channel.state = CHANNEL_STOPPED;
}

/*
  Send message. No locking needed as we only call socket functions
  that are already thread safe.
 */
int message_channel_base_send(message_channel_t *channel, 
                              void *msg, size_t msglen)
{
    message_channel_base_t *base = (message_channel_base_t *)channel;
    int ret = -1, retries = 0;

    assert(channel);

    if (!msg)
        return -1;
    
    if (msglen == 0)
        return 0;

    /*
    LOG_DBG("%s Sending %zu byte message\n",
            channel->name, msglen);
    */

    while (retries++ <= MAX_SEND_RETRIES && ret == -1) {
        if (base->native_socket) {
            ret = sendto(base->sock, msg, msglen, 0,
                         (struct sockaddr *) &base->peer, 
                         base->peer_len);
        } 
#if defined(ENABLE_USERMODE)
        else {
            ret = sendto_sv(base->sock, msg, msglen, 0,
                            (struct sockaddr *) &base->peer, 
                            base->peer_len);
        }
#endif
        if (ret == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                /* Do nothing, this function is not called on a task
                   thread. */
            } else {
                LOG_DBG("family=%d\n", base->peer.sa.sa_family);
                LOG_DBG("%s sendto error: %s\n", 
                        channel->name, strerror(errno));
                break;
            }
        }
    }

    /* LOG_DBG("Sent %d\n", ret); */

    return ret;
}

/*
  Send message with scatter/gather. No locking needed as we only call
  socket functions that are already thread safe.
 */

int message_channel_base_send_iov(message_channel_t *channel, struct iovec *iov,
                                  size_t veclen, size_t msglen)
{
    message_channel_base_t *base = (message_channel_base_t *) channel;
    struct msghdr mh = { &base->peer, 
                         base->peer_len, 
                         iov, veclen, 
                         NULL, 0, 0
    };
    int ret = -1, retries = 0;

    assert(channel);

    if (!iov)
        return -1;

    if (veclen == 0 || msglen == 0)
        return 0;

    /*
    LOG_DBG("%s Sending %zu byte message to the local stack\n", 
            channel->name, msglen);
    */

    while (retries++ <= MAX_SEND_RETRIES && ret == -1) {
        if (base->native_socket) {
            ret = sendmsg(base->sock, &mh, 0);
        } 
#if defined(ENABLE_USERMODE)
        else {
            ret = sendmsg_sv(base->sock, &mh, 0);
        }
#endif
        if (ret == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                //task_block(base->sock, FD_WRITE);
            } else {
                LOG_ERR("%s sendmsg error: %s\n", 
                        channel->name, strerror(errno));
                break;
            }
        }
    }

    return ret;
}

int message_channel_base_start(message_channel_t *channel)
{
    message_channel_base_t *base = (message_channel_base_t *)channel;
    int ret = 0;

    LOG_DBG("Starting %s channel\n", channel->name);

    pthread_mutex_lock(&channel->lock);

    if (channel->state == CHANNEL_INITIALIZED) {
        channel->state = CHANNEL_RUNNING;
        
        ret = task_add(&base->task, message_channel_base_task, base);

        if (ret != 0) {
            channel->state = CHANNEL_INITIALIZED;
        }
    }
    pthread_mutex_unlock(&channel->lock);

    return ret;
}

void message_channel_base_stop(message_channel_t *channel)
{
    message_channel_base_t *base = (message_channel_base_t *)channel;

    assert(channel);

    pthread_mutex_lock(&channel->lock);

    if (channel->state == CHANNEL_RUNNING && base->running) {
        LOG_DBG("Stopping %s channel\n", channel->name);
        base->running = 0;
        pthread_mutex_unlock(&channel->lock);
        task_cancel(base->task);
        task_join(base->task);
        return;
    }
    pthread_mutex_unlock(&channel->lock);
}

static inline int copy_addr(struct sockaddr *to, socklen_t *tolen,
                            const struct sockaddr *from, socklen_t fromlen)
{
    if (*tolen < fromlen)
        return -1;
    
    memcpy(to, from, fromlen);
    *tolen = fromlen;
    return 0;
}

int message_channel_base_get_local(message_channel_t *channel,
                                   struct sockaddr *addr,
                                   socklen_t *addrlen)
{
    message_channel_base_t *base = (message_channel_base_t *)channel;
    int ret;
    assert(channel);
    assert(addr);
    pthread_mutex_lock(&channel->lock);
    ret = copy_addr(addr, addrlen, &base->local.sa, base->local_len);
    pthread_mutex_unlock(&channel->lock);
    return ret;
}

int message_channel_base_get_peer(message_channel_t *channel,
                                  struct sockaddr *addr,
                                  socklen_t *addrlen)
{
    message_channel_base_t *base = (message_channel_base_t *)channel;
    int ret;
    assert(channel);
    assert(addr);
    pthread_mutex_lock(&channel->lock);
    ret = copy_addr(addr, addrlen, &base->peer.sa, base->peer_len);
    pthread_mutex_unlock(&channel->lock);
    return ret;
}

int message_channel_base_set_peer(message_channel_t *channel, 
                                  const struct sockaddr *addr, socklen_t len)
{
    message_channel_base_t *base = (message_channel_base_t *)channel;

    pthread_mutex_lock(&channel->lock);

    if (len > sizeof(base->peer)) {
        pthread_mutex_unlock(&channel->lock);
        return -1;
    }

    if (len > 0) {
        memcpy(&base->peer, addr, len);
        message_channel_rehash(channel);
    }
    pthread_mutex_unlock(&channel->lock);

    return 0;
}

int message_channel_base_init(message_channel_base_t *base,
                              message_channel_type_t type, 
                              int sock_type,
                              int protocol,
                              const struct sockaddr *local,
                              socklen_t local_len,
                              const struct sockaddr *peer,
                              socklen_t peer_len,
                              message_channel_ops_t *ops)
{
    if (!base)
        return -1;
    
    if (peer_len > sizeof(channel_addr_t) || 
        local_len > sizeof(channel_addr_t))
        return -1;
    
    if (message_channel_init(&base->channel, type, ops) == -1)
        return -1;

    base->sock_type = sock_type;
    base->protocol = protocol;
    base->buffer_len = RECV_BUFFER_SIZE;

    if (peer && peer_len > 0) {
        memcpy(&base->peer, peer, peer_len);
        base->peer_len = peer_len;
    }

    if (local && local_len > 0) {
        memcpy(&base->local, local, local_len);
        base->local_len = local_len;
    }

    if (ops)
        base->channel.ops = ops;

    return 0;
}

message_channel_base_t *message_channel_base_create(channel_key_t *key,
                                                    message_channel_ops_t *ops)
{
    message_channel_base_t *base;

    base = malloc(sizeof(message_channel_base_t));

    if (!base)
        return NULL;

    memset(base, 0, sizeof(message_channel_base_t));

    if (message_channel_base_init(base, key->type,
                                  key->sock_type,
                                  key->protocol,
                                  key->local, key->local_len, 
                                  key->peer, key->peer_len, ops)) {
        free(base);
        return NULL;
    }

    base->channel.flags = key->flags;

    return base;
}
