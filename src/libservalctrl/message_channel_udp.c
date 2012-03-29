/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- 
 *
 * UDP-based backend for message channels.
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
#include <sys/socket.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>
#include <common/debug.h>
#include <common/platform.h>
#include <common/atomic.h>
#include <libservalctrl/message_channel.h>
#include <libserval/serval.h>

#include "message_channel_internal.h"
#include "message_channel_base.h"

#define MAX_UDP_PACKET 1368
#define UDP_BUFFER_SIZE 2048

/*
 * Serval unconnected UDP message channels differ from UNIX and UDP
 * channels in that they are point-to-multipoint, while the other two
 * are effectively point-to-point channels. As such, it requires a shared
 * dispatch facility on recv() to shuttle in-bound packets to the proper
 * message channel per remote peer ServiceID.
 *
 * This means that all UDP channels that want to receive on the same
 * port must share a socket, and therefore also a message_channel_base
 * handle. We wrap each unique UDP handle around this shared base
 * handle and use locks to handle simultaneous access.
 */
typedef struct message_channel_udp {
    message_channel_t channel;
    message_channel_base_t *base;
    channel_addr_t peer;
    socklen_t peer_len;
} message_channel_udp_t;

#define UDP_BASE_FLAG 0x1

static ssize_t message_channel_udp_base_recv_callback(message_channel_t *channel, 
                                                      struct message *msg);

int message_channel_udp_equalfn(const message_channel_t *channel, 
                                const void *_key)
{
    const message_channel_udp_t *mcu = (const message_channel_udp_t *)channel;
    channel_key_t *key = (channel_key_t *)_key;

    if (key->type != channel->type)
        return 0;
    
    if (key->peer && key->peer_len > 0 && mcu->peer_len > 0) {
        if (memcmp(key->peer, &mcu->peer, mcu->peer_len) != 0)
            return 0;
    }
    if (key->local && key->local_len > 0 && mcu->base->local_len > 0) {
        if (memcmp(key->local, &mcu->base->local, mcu->base->local_len) != 0)
            return 0;
    }
    return 1;
}

static int message_channel_udp_fillkey(const message_channel_t *channel, 
                                       void *_key)
{
    message_channel_udp_t *mcu = (message_channel_udp_t *)channel;
    channel_key_t *key = (channel_key_t *)_key;
    
    key->type = channel->type;
    key->flags = channel->flags;
    key->local = &mcu->base->local.sa;
    key->local_len = mcu->base->local_len;
    key->peer = &mcu->peer.sa;
    key->peer_len = mcu->peer_len;
    key->sock_type = mcu->base->sock_type;
    key->protocol = mcu->base->protocol;

    return 0;
}

int message_channel_udp_base_equalfn(const message_channel_t *channel, 
                                     const void *_key)
{
    channel_key_t *key = (channel_key_t *)_key;
    return message_channel_base_equalfn(channel, key) && 
        key->flags == channel->flags;
}

static int message_channel_udp_initialize(message_channel_t *channel)
{
    return 0;
}

static void message_channel_udp_finalize(message_channel_t *channel)
{
    message_channel_udp_t *mcu = (message_channel_udp_t *)channel;
    mcu->base->channel.ops->put(&mcu->base->channel);
}

static int message_channel_udp_start(message_channel_t *channel)
{
    message_channel_udp_t *mcu = (message_channel_udp_t *)channel;
    return message_channel_start(&mcu->base->channel);
}

static void message_channel_udp_stop(message_channel_t *channel)
{
    message_channel_udp_t *mcu = (message_channel_udp_t *)channel;
    message_channel_stop(&mcu->base->channel);
}

static int message_channel_udp_get_local(message_channel_t *channel,
                                         struct sockaddr *addr,
                                         socklen_t *addrlen)
{
    message_channel_udp_t *mcu = (message_channel_udp_t *)channel;
    int ret;
    pthread_mutex_lock(&channel->lock);
    /* memcpy(addr, &mcu->base->local, mcu->base->local_len);
    *addrlen = mcu->base->local_len;
    */
    ret = getsockname(mcu->base->sock, addr, addrlen);
    pthread_mutex_unlock(&channel->lock);
    return ret;
}

static int message_channel_udp_get_peer(message_channel_t *channel,
                                        struct sockaddr *addr,
                                        socklen_t *addrlen)
{
    message_channel_udp_t *mcu = (message_channel_udp_t *)channel;
    pthread_mutex_lock(&channel->lock);
    memcpy(addr, &mcu->peer, mcu->peer_len);
    *addrlen = mcu->peer_len;
    pthread_mutex_unlock(&channel->lock);
    return 0;
}

static int message_channel_udp_set_peer(message_channel_t *channel, 
                                        const struct sockaddr *addr, 
                                        socklen_t addrlen)
{
    message_channel_udp_t *mcu = (message_channel_udp_t *)channel;
    pthread_mutex_lock(&channel->lock);
    memcpy(&mcu->peer, addr, mcu->peer_len);
    mcu->peer_len = addrlen;
    pthread_mutex_unlock(&channel->lock);
    return 0;
}

static int message_channel_udp_send(message_channel_t *channel, 
                                    void *msg, size_t msglen)
{
    message_channel_udp_t *mcu = (message_channel_udp_t *)channel;
    int ret;

    pthread_mutex_lock(&mcu->base->channel.lock);
    memcpy(&mcu->base->peer, &mcu->peer, mcu->peer_len);
    mcu->base->peer_len = mcu->peer_len;
    ret = mcu->base->channel.ops->send(&mcu->base->channel, msg, msglen);
    mcu->base->peer_len = 0;
    pthread_mutex_unlock(&mcu->base->channel.lock);

    return ret;
}

static int message_channel_udp_send_iov(message_channel_t *channel, 
                                        struct iovec *iov,
                                        size_t veclen, size_t msglen)
{
    message_channel_udp_t *mcu = (message_channel_udp_t *)channel;
    int ret;

    pthread_mutex_lock(&mcu->base->channel.lock);
    memcpy(&mcu->base->peer, &mcu->peer, mcu->peer_len);
    mcu->base->peer_len = mcu->peer_len;
    ret = mcu->base->channel.ops->send_iov(&mcu->base->channel, 
                                           iov, veclen, msglen);
    mcu->base->peer_len = 0;
    pthread_mutex_unlock(&mcu->base->channel.lock);

    return ret;
}

struct message_channel_ops udp_base_ops = {
    .initialize = message_channel_base_initialize,
    .start = message_channel_base_start,
    .stop = message_channel_base_stop,
    .finalize = message_channel_base_finalize,
    .hold = message_channel_internal_hold,
    .put = message_channel_internal_put,
    .hashfn = message_channel_internal_hashfn,
    .equalfn = message_channel_udp_base_equalfn,
    .fillkey = message_channel_base_fillkey,
    .get_local = message_channel_base_get_local,
    .set_peer = message_channel_base_set_peer,
    .get_peer = message_channel_base_get_peer,
    .register_callback = message_channel_internal_register_callback,
    .unregister_callback = message_channel_internal_unregister_callback,
    .get_callback_count = message_channel_internal_get_callback_count,
    .send = message_channel_base_send,
    .send_iov = message_channel_base_send_iov,
    .recv = message_channel_base_recv,
    .recv_callback = message_channel_udp_base_recv_callback,
    .task = message_channel_base_task,
};

struct message_channel_ops udp_ops = {
    .initialize = message_channel_udp_initialize,
    .start = message_channel_udp_start,
    .stop = message_channel_udp_stop,
    .finalize = message_channel_udp_finalize,
    .hold = message_channel_internal_hold,
    .put = message_channel_internal_put,
    .hashfn = message_channel_internal_hashfn,
    .equalfn = message_channel_udp_equalfn,
    .fillkey = message_channel_udp_fillkey,
    .get_local = message_channel_udp_get_local,
    .set_peer = message_channel_udp_set_peer,
    .get_peer = message_channel_udp_get_peer,
    .register_callback = message_channel_internal_register_callback,
    .unregister_callback = message_channel_internal_unregister_callback,
    .get_callback_count = message_channel_internal_get_callback_count,
    .send = message_channel_udp_send,
    .send_iov = message_channel_udp_send_iov,
    .recv_callback = message_channel_internal_recv_callback,
};

ssize_t message_channel_udp_base_recv_callback(message_channel_t *channel,
                                               struct message *msg)
{
    message_channel_base_t *base = (message_channel_base_t *)channel;
    message_channel_udp_t *mcu;
    /* Use base->local_len in key for msg->from.sa because the address
     * len in msg may include both AF_SERVAL and AF_INET addreses,
     * while base is only one AF_SERVAL address. */
    channel_key_t key = { MSG_CHANNEL_UDP, 0, SOCK_DGRAM, 0,
                          &base->local.sa, base->local_len, 
                          &msg->from.sa, base->local_len }; 
    ssize_t ret;

    mcu = (message_channel_udp_t *)message_channel_lookup(&key, udp_ops.hashfn);

    if (!mcu) {
        LOG_ERR("Could not find UDP channel handle\n");
        return -1;
    }

    ret = mcu->channel.ops->recv_callback(&mcu->channel, msg);

    message_channel_put(&mcu->channel);

    return ret;
}

static const char *udp_base_name = "UDP_BASE";

message_channel_t *message_channel_udp_create(channel_key_t *key)
{
    message_channel_udp_t *mcu;
    channel_key_t base_key = { MSG_CHANNEL_UDP, UDP_BASE_FLAG, 
                               SOCK_DGRAM, 0,
                               key->local, key->local_len, 
                               NULL, 0 };

    if (!key || !key->local)
        return NULL;

    mcu = malloc(sizeof(message_channel_udp_t));

    if (!mcu)
        return NULL;

    memset(mcu, 0, sizeof(message_channel_udp_t));

    if (message_channel_init(&mcu->channel, 
                             key->type, &udp_ops) == -1) {
        free(mcu);
        return NULL;
    }
    
    memcpy(&mcu->peer, key->peer, key->peer_len);
    mcu->peer_len = key->peer_len;
    
    mcu->base = (message_channel_base_t *)
        message_channel_lookup(&base_key, udp_base_ops.hashfn);
    
    if (!mcu->base) {
        mcu->base = (message_channel_base_t *)
            message_channel_base_create(&base_key, 
                                        sizeof(*mcu->base),
                                        &udp_base_ops);
        if (!mcu->base) {
            message_channel_put(&mcu->channel);
            return NULL;
        }
        
        mcu->base->channel.name = udp_base_name;
        
        if (mcu->base->channel.ops->initialize(&mcu->base->channel)) {
            LOG_ERR("Channel initialization failed\n");
            goto fail_base_init;
        }
    }

    return &mcu->channel;
 fail_base_init:
    message_channel_put(&mcu->base->channel);
    message_channel_put(&mcu->channel);
    return NULL;
}
