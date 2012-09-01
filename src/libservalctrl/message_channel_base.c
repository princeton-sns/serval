/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 *
 * Socket-based message channel.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 *          David Shue <dshue@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
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
    const message_channel_base_t *base = 
        (const message_channel_base_t *)channel;

    if (key->type != channel->type ||
        //key->sock_type != base->sock_type ||
        key->protocol != base->protocol)
        return 0;
    
    if (key->peer && key->peer_len > 0 && base->peer_len > 0) {
        if (memcmp(key->peer, &base->peer, base->peer_len) != 0)
            return 0;
    }

    if (key->local && key->local_len > 0 && base->local_len > 0) {
        if (memcmp(key->local, &base->local, base->local_len) != 0)
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
    
    err = signal_init(&base->exit_signal);

    if (err == -1)
        return -1;

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
            err = -1;
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

    signal_destroy(&base->exit_signal);

    channel->state = CHANNEL_CREATED;
}

static void *thread_start(void *arg)
{
    message_channel_t *channel = (message_channel_t *)arg;

    if (channel->ops->task)
        channel->ops->task(channel);
    
    return NULL;
}

ssize_t message_channel_base_recv(struct message_channel *channel, 
                                  struct message **msg)
{
    message_channel_base_t *base = (message_channel_base_t *)channel;
    message_t *m;
    ssize_t ret;
   
    m = message_alloc(NULL, RECV_BUFFER_SIZE);

    if (!m)
        return -1;

    /* Default to channel's stored peer address in case this is a
     * connected socket */

    if (base->peer_len > 0) {
        memcpy(&m->from.sa, &base->peer.sa, base->peer_len);
        m->from_len = base->peer_len;
    } else {
        m->from_len = sizeof(m->from);
    }

    if (base->native_socket) {
        ret = recvfrom(base->sock, m->data,
                       m->length, 0,
                       &m->from.sa, &m->from_len);
    } 
#if defined(ENABLE_USERMODE)
    else {
        ret = recvfrom_sv(base->sock, m->data,
                          m->length, 0,
                          &m->from.sa, &m->from_len);
    }
#endif
    
    if (ret > 0) {
        m->length = ret;
        *msg = m;
    } else {
        message_put(m);
    }
    
    return ret;
} 

int message_channel_base_task(struct message_channel *channel)
{
    message_channel_base_t *base = (message_channel_base_t *)channel;
    struct message *msg;
    ssize_t ret = -1;

    message_channel_internal_on_start(&base->channel);

    while (base->running) {
        ret = base->channel.ops->recv(channel, &msg);
        
        if (ret == -1) {
            if (errno == EAGAIN || 
                errno == EWOULDBLOCK) {
                struct pollfd pfd[2];

                pfd[0].fd = base->sock;
                pfd[0].events = POLLIN | POLLERR | POLLHUP;
                pfd[0].revents = 0;
                
                pfd[1].fd = signal_get_fd(&base->exit_signal);
                pfd[1].events = POLLIN | POLLERR | POLLHUP;
                pfd[1].revents = 0;
                
                ret = poll(pfd, 2, -1);

                if (ret > 0) {
                    if (pfd[0].revents & POLLIN)
                        continue;
                    else if (pfd[0].revents & POLLHUP) {
                        LOG_DBG("%s other end closed?\n",
                                base->channel.name);
                        base->running = 0;
                    } else if (pfd[1].revents) {
                        /* Check for exit signal */
                        LOG_DBG("%s should exit\n", base->channel.name);
                        base->running = 0;
                    } 
                } else if (ret == -1) {
                    LOG_ERR("%s poll error: %s\n",
                            base->channel.name, strerror(errno));
                    base->running = 0;
                }
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
            LOG_DBG("%s Received a message len=%zd\n", 
                    base->channel.name, ret);
            
            if (channel->ops->recv_callback)
                ret = channel->ops->recv_callback(channel, msg);
        }
    }
    LOG_DBG("%s task exits\n", base->channel.name);
    base->channel.state = CHANNEL_STOPPED;
    message_channel_internal_on_stop(&base->channel);

    return ret;
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
    struct iovec iov = { msg, msglen };
    struct msghdr msgh = { &base->peer, 
                           base->peer_len,
                           &iov, 1,
                           &channel->peer_pid,
                           sizeof(channel->peer_pid), 0 };
    
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
            ret = sendmsg(base->sock, &msgh, 0);
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
                /* Retry... */
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
        
        base->should_join = 1;

        ret = pthread_create(&base->thread, NULL, 
                             thread_start, channel);
        if (ret != 0) {
            channel->state = CHANNEL_INITIALIZED;
            base->should_join = 0;
        }
    }
    pthread_mutex_unlock(&channel->lock);

    return ret;
}

void message_channel_base_stop(message_channel_t *channel)
{
    message_channel_base_t *base = (message_channel_base_t *)channel;
    int ret;

    assert(channel);

    pthread_mutex_lock(&channel->lock);

    if (channel->state == CHANNEL_RUNNING) {

        LOG_DBG("Stopping %s channel\n", channel->name);
        base->running = 0;
        pthread_mutex_unlock(&channel->lock);

        ret = signal_raise(&base->exit_signal);

        if (ret == -1) {
            LOG_ERR("Could not raise signal\n");
        }
    }

    if (base->should_join) {
        ret = pthread_join(base->thread, NULL);
        
        if (ret != 0) {
            LOG_ERR("Could not join with send channel thread\n");
        } else {
            LOG_DBG("Channel %s stopped\n", channel->name);
        }
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

    if (peer && peer_len > 0) {
        memcpy(&base->peer, peer, peer_len);
        base->peer_len = peer_len;
    }

    if (local && local_len > 0) {
        memcpy(&base->local, local, local_len);
        base->local_len = local_len;
#if defined(ENABLE_DEBUG)
        if (base->local.sa.sa_family == AF_INET) { 
            char ip1[18];
            
            LOG_DBG("init local=%s\n",
                    inet_ntop(AF_INET, &base->local.in.sin_addr, ip1, sizeof(ip1)));
        }
#endif

    }

    if (ops)
        base->channel.ops = ops;

    return 0;
}

message_channel_t *message_channel_base_create(channel_key_t *key,
                                               size_t size,
                                               message_channel_ops_t *ops)
{
    message_channel_base_t *base;
    
    if (size < sizeof(message_channel_base_t))
        return NULL;
    
    base = malloc(size);
    
    if (!base)
        return NULL;

    memset(base, 0, size);

    if (message_channel_base_init(base, key->type,
                                  key->sock_type,
                                  key->protocol,
                                  key->local, key->local_len, 
                                  key->peer, key->peer_len, ops) == -1) {
        free(base);
        return NULL;
    }

    base->channel.flags = key->flags;

    return &base->channel;
}
