/*
 * message_channel.c
 *
 *  Created on: Feb 11, 2011
 *      Author: daveds
 */

#include <sys/socket.h>

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <glib.h>
#include <netinet/in.h>
#include <unistd.h>

#include "debug.h"
#include "message_channel.h"
#include "message_channel_base.h"
#include "task.h"
#include "service_util.h"
#include "libserval/serval.h"
#include "serval/platform.h"
#include "serval/atomic.h"

#define MAX_UDP_PACKET 1368
#define UDP_BUFFER_SIZE 2048

/*
 * Serval unconnected UDP message channels differ from unix and udp
 * channels in that they are point to multi-point, where as the other two
 * are effectively point to point channels. As such, it requires a shared
 * dispatch facility on recv() to shuttle in-bound packets to the proper
 * message channel per remote peer SID
 */

/* big question is outbound (send) buffer management, especially
 * if messages are being cached by the rpc manager.
 * Currently the assumption is that the calling object (resolver
 * or service path interface) is marshaling the rpc data into the
 * message and transferring control/ownership to the rpc stack.
 * Alternatively, the rpc stack can make an explicit copy of the
 * data on refcount = 0.
 */
#define UDP_MC_CALLBACKS 2
struct sv_udp_message_channel {
    struct sv_instance_addr remote;
    size_t remote_len;
    atomic_t ref_count;
    message_channel_callback callbacks[UDP_MC_CALLBACKS];
    struct sv_udp_message_dispatch* dispatch;
};

struct sv_udp_message_dispatch {
    struct sockaddr_sv local;

    int sock;

    atomic_t ref_count;
    atomic_t running;

    task_mutex mutex;

    char* buffer;
    size_t buffer_len;
    task_handle_t recv_task;
    GHashTable* dispatch_table;
    struct sv_udp_message_channel* default_channel;
};

/* global serval udp dispatch table */
static GHashTable* udp_dispatch_table = NULL;
static int native_serval = 0;

/* TODO - might need to be a r/w lock */
static task_mutex udp_dispatch_mutex = TASK_MUTEX_INITIALIZER;

static int udp_initialize(void* channel);
static void udp_start(void* channel);
static void udp_stop(void* channel);
static int udp_finalize(void* channel);
static const struct sockaddr* udp_get_local_address(void* target, int* len);
static void udp_set_peer_address(void* target, struct sockaddr* addr, size_t len);
static const struct sockaddr* udp_get_peer_address(void* target, int* len);

static int udp_register_callback(void* target, message_channel_callback* cb);
static int udp_unregister_callback(void* target, message_channel_callback* cb);
static int udp_get_callback_count(void* target);

static int udp_send(void* channel, void *message, size_t datalen);
static int udp_send_iov(void* target, struct iovec* iov, size_t veclen, size_t len);
static int udp_recv(void* channel, const void *message, size_t datalen);
static int udp_get_max_message_size(void* channel) {
    return MAX_UDP_PACKET;
}

static struct sv_message_channel_interface udp_mc_interface = {
        .initialize = udp_initialize,
        .start = udp_start,
        .stop = udp_stop,
        .finalize = udp_finalize,
        .get_local_address = udp_get_local_address,
        .set_peer_address = udp_set_peer_address,
        .get_peer_address = udp_get_peer_address,
        .get_max_message_size = udp_get_max_message_size,
        .register_callback = udp_register_callback,
        .unregister_callback = udp_unregister_callback,
        .get_callback_count = udp_get_callback_count,
        .send_message = udp_send,
        .send_message_iov = udp_send_iov,
        .recv_message = udp_recv };

static struct sv_udp_message_dispatch* create_udp_message_dispatch(struct sockaddr_sv* local,
        int buffer_len);
static int message_dispatch_initialize(struct sv_udp_message_dispatch* dispatch);
static void message_dispatch_start(struct sv_udp_message_dispatch* dispatch);
static void message_dispatch_stop(struct sv_udp_message_dispatch* dispatch);
static void message_dispatch_finalize(struct sv_udp_message_dispatch* dispatch);
static int message_dispatch_recv(struct sv_udp_message_dispatch* dispatch);
static int message_dispatch_recv(struct sv_udp_message_dispatch* dispatch);
static void message_dispatch_recv_task(void* target);

static inline void udp_incref(struct sv_udp_message_channel* channel) {
    assert(channel);
    atomic_inc(&channel->ref_count);
}

static inline void udp_decref(struct sv_udp_message_channel* channel) {
    assert(channel);
    if(atomic_dec_and_test(&channel->ref_count)) {

        udp_finalize(channel);
        free(channel);
    }
}

/* hash table dealloc helper functions: key, value */
//static void destroy_sock_key(void* key) {
//    if(key) {
//        free(key);
//    }
//}

//static void destroy_message_dispatch(void* value) {
//    if(value) {
//        //TODO
//        //struct sv_udp_message_dispatch* dispatch = (struct sv_udp_message_dispatch*) value;
//        //message_dispatch_decref(dispatch);
//    }
//}

/* called to cleanup any static/global shared udp channel state
 * generally on system exit
 */
void udp_channel_destroy() {
    if(udp_dispatch_table) {
        g_hash_table_destroy(udp_dispatch_table);
        //free(udp_dispatch_table);
        udp_dispatch_table = NULL;
    }

    task_mutex_destroy(&udp_dispatch_mutex);
}

void udp_channel_create() {
    udp_dispatch_table = g_hash_table_new_full(service_id_prefix_hash, service_id_prefix_equal,
            NULL, NULL);
}

/* include buffer len as well, for consistency? */
int create_udp_message_channel(struct sockaddr_sv* local, struct sv_instance_addr* remote,
        int buffer_len, message_channel_callback* callback, message_channel* channel) {

    if(local == NULL || remote == NULL) {
        return -1;
    }

    //udp_channel_create();
    int retval = 0;
    task_mutex_lock(&udp_dispatch_mutex);

    assert(udp_dispatch_table);
    struct sv_udp_message_dispatch* dispatch =
            (struct sv_udp_message_dispatch*) g_hash_table_lookup(udp_dispatch_table,
                    &local->sv_srvid);

    if(dispatch == NULL) {
        dispatch = create_udp_message_dispatch(local, buffer_len);
        /* TODO if message dispatch fails, everything should fail
         * or at least operate in local-only mode
         * */
        g_hash_table_insert(udp_dispatch_table, &local->sv_srvid, dispatch);
    }

    task_mutex_lock(&dispatch->mutex);

    struct sv_udp_message_channel* uchannel = (struct sv_udp_message_channel*) g_hash_table_lookup(
            dispatch->dispatch_table, &remote->service.sv_srvid);

    if(uchannel) {
        if(uchannel->callbacks[0].target == NULL) {
            uchannel->callbacks[0] = *callback;
        } else if(uchannel->callbacks[1].target == NULL) {
            uchannel->callbacks[1] = *callback;
        } else {
            LOG_ERR("No callback slots available!");
            retval = -1;
            goto error;
        }
    } else {
        uchannel = (struct sv_udp_message_channel*) malloc(sizeof(*uchannel));
        bzero(uchannel, sizeof(*uchannel));

        uchannel->callbacks[0] = *callback;

        memcpy(&uchannel->remote, remote, sizeof(struct sv_instance_addr));

        if(remote->address.sin.sin_addr.s_addr == 0) {
            uchannel->remote_len = sizeof(struct sockaddr_sv);
            dispatch ->default_channel = uchannel;
        } else {
            uchannel->remote_len = sizeof(struct sv_instance_addr);
        }

        uchannel->dispatch = dispatch;
        g_hash_table_insert(dispatch->dispatch_table, &remote->service.sv_srvid, uchannel);

    }

    udp_incref(uchannel);
    task_mutex_unlock(&dispatch->mutex);
    task_mutex_unlock(&udp_dispatch_mutex);

    channel->target = uchannel;
    channel->interface = &udp_mc_interface;
    goto out;

    error: task_mutex_unlock(&dispatch->mutex);
    task_mutex_unlock(&udp_dispatch_mutex);

    out: return retval;
}

static int udp_register_callback(void* target, message_channel_callback* cb) {
    assert(target);
    assert(cb);
    struct sv_udp_message_channel* uchannel = (struct sv_udp_message_channel*) target;

    if(uchannel->callbacks[0].target == NULL) {
        uchannel->callbacks[0] = *cb;
    } else if(uchannel->callbacks[1].target == NULL) {
        uchannel->callbacks[1] = *cb;
    } else {
        return -1;
    }
    return 0;
}
static int udp_unregister_callback(void* target, message_channel_callback* cb) {
    assert(target);
    struct sv_udp_message_channel* uchannel = (struct sv_udp_message_channel*) target;

    if(uchannel->callbacks[0].target == cb->target) {
        uchannel->callbacks[0].target = NULL;
        uchannel->callbacks[0].recv_message = NULL;
        return 0;
    }
    if(uchannel->callbacks[1].target == cb->target) {
        uchannel->callbacks[1].target = NULL;
        uchannel->callbacks[1].recv_message = NULL;
        return 0;
    }

    return -1;
}
static int udp_get_callback_count(void* target) {
    assert(target);
    struct sv_udp_message_channel* uchannel = (struct sv_udp_message_channel*) target;

    int count = 0;
    int i;
    for (i = 0; i < UDP_MC_CALLBACKS; i++) {

        if(uchannel->callbacks[i].target) {
            count++;
        }
    }

    return count;
}

static int udp_initialize(void* target) {
    assert(target);
    struct sv_udp_message_channel* uchannel = (struct sv_udp_message_channel*) target;

    return message_dispatch_initialize(uchannel->dispatch);
}

static void udp_start(void* target) {
    assert(target);
    struct sv_udp_message_channel* uchannel = (struct sv_udp_message_channel*) target;

    message_dispatch_start(uchannel->dispatch);

}

static void udp_stop(void* target) {
    assert(target);
    struct sv_udp_message_channel* uchannel = (struct sv_udp_message_channel*) target;

    message_dispatch_stop(uchannel->dispatch);

}

/* Lock required?*/
static void udp_set_peer_address(void* target, struct sockaddr* addr, size_t len) {
    assert(target);

    if(addr == NULL) {
        return;
    }

    struct sv_udp_message_channel* uchannel = (struct sv_udp_message_channel*) target;
    /* lock? TODO */

    if(len == sizeof(struct sv_instance_addr)) {
        memcpy(&uchannel->remote, addr, len);
    } else if(len == sizeof(struct sockaddr_sv)) {
        /* dangerous if the local addr reference is owned elsewhere TODO*/
        memcpy(&uchannel->remote.service, addr, len);
    } else if(len == sizeof(struct sockaddr_in) || len == sizeof(struct sockaddr_in6)) {
        memcpy(&uchannel->remote.address, addr, len);
    }
}

static const struct sockaddr* udp_get_peer_address(void* target, int* len) {
    assert(target);
    struct sv_udp_message_channel* uchannel = (struct sv_udp_message_channel*) target;
    *len = sizeof(struct sv_instance_addr);
    return (struct sockaddr*) &uchannel->remote;
}

static const struct sockaddr* udp_get_local_address(void* target, int* len) {
    assert(target);
    struct sv_udp_message_channel* uchannel = (struct sv_udp_message_channel*) target;
    *len = sizeof(uchannel->dispatch->local);
    return (struct sockaddr*) &uchannel->dispatch->local;
}

//include net_addr parameter?
/* assume that the global lock has been obtained
 * initialize and create the channel socket */
static struct sv_udp_message_dispatch* create_udp_message_dispatch(struct sockaddr_sv* local,
        int buffer_len) {

    struct sv_udp_message_dispatch* dispatch = (struct sv_udp_message_dispatch*) malloc(
            sizeof(struct sv_udp_message_dispatch));

    if(dispatch == NULL) {
        LOG_ERR("Could not allocate memory for udp message channel dispatch!");
        return NULL;
    }

    bzero(dispatch, sizeof(*dispatch));

    dispatch->dispatch_table = g_hash_table_new_full(service_id_prefix_hash,
            service_id_prefix_equal, NULL, NULL);

    if(buffer_len > 0) {
        dispatch->buffer_len = buffer_len;
    } else {
        dispatch->buffer_len = UDP_BUFFER_SIZE;
    }

    memcpy(&dispatch->local, local, sizeof(*local));
    task_mutex_init(&dispatch->mutex);

    return dispatch;
}

static void udp_channel_remove(struct sv_udp_message_dispatch* dispatch) {
    if(udp_dispatch_table == NULL || dispatch == NULL) {
        return;
    }

    //task_mutex_lock(&udp_dispatch_mutex);
    g_hash_table_remove(udp_dispatch_table, &dispatch->local.sv_srvid);
    //task_mutex_unlock(&udp_dispatch_mutex);
}

static int message_dispatch_initialize(struct sv_udp_message_dispatch* dispatch) {
    //dispatch is on the top 96 bits of the serviceID - does not include host key
    //TODO - need to be careful here - the serviceID's are not managed here unless it's refcounting
    //neither are the message channels themselves
    assert(dispatch);
    /* add the dispatch to the global table */
    if(dispatch->sock > 0) {
        return 0;
    }

    if(dispatch->dispatch_table == NULL) {
        dispatch->dispatch_table = g_hash_table_new_full(service_id_prefix_hash,
                service_id_prefix_equal, NULL, NULL);
    }

    dispatch->buffer = (char*) malloc(dispatch->buffer_len);

    if(dispatch->buffer == NULL) {
        LOG_ERR("Could not allocate udp dispatch buffer: %u", dispatch->buffer_len);
        return -1;
    }
    bzero(dispatch->buffer, dispatch->buffer_len);
    //    struct sockaddr_sv local_addr;
    //    local_addr.sv_family = AF_SERVAL;
    //    local_addr.sv_flags = SVSF_HOST_SCOPE | SVSF_STRICT_SCOPE;
    //    local_addr.sv_prefix_bits = 96;
    //    local_addr.sv_srvid = local.sv_srvid;

    int sock = socket(AF_SERVAL, SOCK_DGRAM, 0);

    if(sock == -1) {
        switch (errno) {
        case EAFNOSUPPORT:
        case EPROTONOSUPPORT:
            /* Try libserval */
            sock = socket_sv(AF_SERVAL, SOCK_DGRAM, 0);

            if(sock == -1) {
                LOG_ERR("Could not create controller socket: %s\n", strerror_sv(errno));
                return -1;
            }
            native_serval = 0;
            break;
        default:
            LOG_ERR("Could not create controller socket (native): %s\n", strerror(errno));
            return -1;
        }
    } else {
        native_serval = 1;
    }
    LOG_DBG("Using: %i serval to bind on sock(%i) for service id: %s prefix: %i\n", native_serval, sock, service_id_to_str(&dispatch->local.sv_srvid), dispatch->local.sv_prefix_bits);
    set_reuse_ok(sock);

    int retval = 0;

    if(native_serval) {
        retval = bind(sock, (struct sockaddr*) &dispatch->local, sizeof(struct sockaddr_sv));
    } else {
        retval = bind_sv(sock, (struct sockaddr*) &dispatch->local, sizeof(struct sockaddr_sv));
    }

    if(retval < 0) {
        fprintf(stderr, "Error binding socket: %s\n", strerror(errno));
        goto error;
    }

    //fprintf(stdout, "server: bound to object id %d\n", ECHO_OBJECT_ID);

    make_async(sock);

    dispatch->sock = sock;

    out: return retval;

    error: task_mutex_lock(&udp_dispatch_mutex);
    message_dispatch_finalize(dispatch);
    task_mutex_unlock(&udp_dispatch_mutex);

    goto out;
}

static void message_dispatch_start(struct sv_udp_message_dispatch* dispatch) {
    assert(dispatch);

    task_mutex_lock(&dispatch->mutex);
    if(atomic_read(&dispatch->running)) {
        task_mutex_unlock(&dispatch->mutex);
        return;
    }
    atomic_set(&dispatch->running, 1);
    task_mutex_unlock(&dispatch->mutex);

    dispatch->recv_task = task_add(dispatch, message_dispatch_recv_task);

}

static void message_dispatch_stop(struct sv_udp_message_dispatch* dispatch) {
    assert(dispatch);

    if(atomic_read(&dispatch->running)) {
        atomic_set(&dispatch->running, 0);
        task_unblock(dispatch->sock, FD_ALL);
        task_remove(dispatch->recv_task);
    }

}

static void message_dispatch_finalize(struct sv_udp_message_dispatch* dispatch) {
    assert(dispatch);

    udp_channel_remove(dispatch);

    if(atomic_read(&dispatch->running)) {
        message_dispatch_stop(dispatch);
    }

    if(dispatch->dispatch_table) {
        g_hash_table_destroy(dispatch->dispatch_table);
        //free(dispatch->dispatch_table);
        dispatch->dispatch_table = NULL;
    }

    if(dispatch->buffer) {
        free(dispatch->buffer);
        dispatch->buffer = NULL;
    }

    if(dispatch->sock > 0) {
        close(dispatch->sock);
        dispatch->sock = 0;
    }

    //if(atomic_read(&dispatch->refcount) == 0) {
    /*TODO - potential race conditions - locking?*/task_mutex_destroy(&dispatch->mutex);
    //}

}

static void message_dispatch_recv_task(void* target) {
    message_dispatch_recv((struct sv_udp_message_dispatch*) target);
}

static int message_dispatch_recv(struct sv_udp_message_dispatch* dispatch) {
    //read from the sock and dispatch the message - sanity check the message type/length first
    assert(dispatch);

    int ret = 1;
    int slen = sizeof(struct sv_instance_addr);
    struct sv_instance_addr peer;

    while (atomic_read(&dispatch->running) && ret) {
        if(native_serval) {
            ret = recvfrom(dispatch->sock, dispatch->buffer, (size_t) dispatch->buffer_len, 0,
                    (struct sockaddr*) &peer, (socklen_t*) &slen);
        } else {
            ret = recvfrom_sv(dispatch->sock, dispatch->buffer, (size_t) dispatch->buffer_len, 0,
                    (struct sockaddr*) &peer, (socklen_t*) &slen);
        }

        if(ret == -1) {
            if(errno == EAGAIN || errno == EWOULDBLOCK) {
                LOG_DBG("serval udp recv would block\n");
                task_block(dispatch->sock, FD_READ);
                continue;
            }

            LOG_ERR("recv error: %s, breaking the read loop\n", strerror(errno));
            //fini?
            atomic_set(&dispatch->running, 0);
            return ret;
        }

        //assume that the buffer is passed directly - meaning
        //no multi-threaded reads - only one message can be processed
        //at a time and all data must be copied out of the buffer
        //TODO crc check or other authentication data?
        task_mutex_lock(&dispatch->mutex);
        struct sv_udp_message_channel* channel =
                (struct sv_udp_message_channel*) g_hash_table_lookup(dispatch->dispatch_table,
                        &peer.service.sv_srvid);

        LOG_DBG("Received UDP %i byte message from %s\n", ret, service_id_to_str(&channel->remote.service.sv_srvid));

        /*TODO should this always set the peer address?*/
        if(channel) {
            /* the "connected" channel, or rather peer-associated channel */
            udp_incref(channel);
        } else if(dispatch->default_channel) {
            /*in essence, this is the "listening" channel*/
            channel = dispatch->default_channel;
            udp_incref(channel);
            udp_set_peer_address(channel, (struct sockaddr*) &peer, slen);
        }

        if(channel) {
            udp_recv(channel, dispatch->buffer, ret);
            udp_decref(channel);
        } else {
            LOG_ERR("No message callback for remote service id: %s", service_id_to_str(&peer.service.sv_srvid));
        }

        /* should probably be a read lock here ...*/task_mutex_unlock(&dispatch->mutex);
    }

    return ret;
}

static int udp_finalize(void* target) {
    //remove from the dispatch table
    assert(target);
    struct sv_udp_message_channel* uchannel = (struct sv_udp_message_channel*) target;

    if(uchannel->dispatch) {
        task_mutex_lock(&udp_dispatch_mutex);
        task_mutex_lock(&uchannel->dispatch->mutex);
        g_hash_table_remove(((struct sv_udp_message_channel*) target)->dispatch->dispatch_table,
                &uchannel->remote.service.sv_srvid);
        task_mutex_unlock(&uchannel->dispatch->mutex);

        assert(uchannel->dispatch->dispatch_table);
        if(g_hash_table_size(uchannel->dispatch->dispatch_table) == 0) {
            message_dispatch_finalize(uchannel->dispatch);
            free(uchannel->dispatch);
        }
        task_mutex_unlock(&udp_dispatch_mutex);

        uchannel->dispatch = NULL;
    }

    return 0;
}

static int udp_recv(void* target, const void *message, size_t datalen) {
    assert(target);
    struct sv_udp_message_channel* channel = (struct sv_udp_message_channel*) target;

    int retval = -1;
    if(channel->callbacks[0].target) {
        retval = channel->callbacks[0].recv_message(channel->callbacks[0].target, message, datalen);
    }

    if(retval && channel->callbacks[1].target) {
        retval = channel->callbacks[1].recv_message(channel->callbacks[1].target, message, datalen);
    }
    /* TODO - error if both callbacks are NULL! */

    return retval;
}

static int udp_send_iov(void* target, struct iovec* iov, size_t veclen, size_t len) {
    assert(target);

    if(iov == NULL) {
        return EINVAL;
    }
    if(veclen == 0 || len == 0) {
        return 0;
    }

    //sanity check the length
    if(len > MAX_UDP_PACKET) {
        //should have been packetized at upper layers into multiple messages
        LOG_ERR("UDP message length exceeds max udp packet: %i", len);
        return -1;
    }

    struct sv_udp_message_channel* uchannel = (struct sv_udp_message_channel*) target;

    LOG_DBG("Sending UDP %i byte message to %s\n", len, service_id_to_str(&uchannel->remote.service.sv_srvid));
    struct msghdr mh = { &uchannel->remote, uchannel->remote_len, iov, veclen, NULL, 0, 0 };
    //return ;
    int retval = -1;
    int retries = 0;

    while (atomic_read(&uchannel->dispatch->running) && retval < 0 && retries < MAX_MESSAGE_RETRIES) {
        retries++;

        if(native_serval) {
            retval = sendmsg(uchannel->dispatch->sock, &mh, 0);
        } else {
            LOG_ERR("Non-native sendmsg not supported!\n");
            return ENOTSUP;
        }

        if(retval == -1) {
            if(errno == EAGAIN || errno == EWOULDBLOCK) {
                task_block(uchannel->dispatch->sock, FD_WRITE);
                continue;
            } else {
                return retval;
            }
        }
    }

    return retval;
}

static int udp_send(void* target, void* message, size_t len) {
    assert(target);

    if(message == NULL) {
        LOG_ERR("Cannot send null udp message!");
        return -1;
    }

    //sanity check the length
    if(len > MAX_UDP_PACKET) {
        //should have been packetized at upper layers into multiple messages
        LOG_ERR("UDP message length exceeds max udp packet: %i", len);
        return -1;
    }

    if(len <= 0) {
        LOG_ERR("UDP message length is zero!");
        return -1;
    }
    struct sv_udp_message_channel* uchannel = (struct sv_udp_message_channel*) target;

    LOG_DBG("Sending UDP %i byte message to %s\n", len, service_id_to_str(&uchannel->remote.service.sv_srvid));
    int retval = -1;

    int retries = 0;

    while (atomic_read(&uchannel->dispatch->running) && retval < 0 && retries < MAX_MESSAGE_RETRIES) {
        retries++;

        if(native_serval) {
            retval = sendto(uchannel->dispatch->sock, message, len, 0,
                    (struct sockaddr*) &uchannel->remote, uchannel->remote_len);
        } else {
            retval = sendto_sv(uchannel->dispatch->sock, message, len, 0,
                    (struct sockaddr*) &uchannel->remote, uchannel->remote_len);
        }

        if(retval == -1) {
            if(errno == EAGAIN || errno == EWOULDBLOCK) {
                task_block(uchannel->dispatch->sock, FD_WRITE);
                continue;
            } else {
                return retval;
            }
        }
    }

    return retval;
}
