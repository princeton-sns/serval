/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <libservalctrl/message_channel.h>
#include <netinet/in.h>
#include <netinet/serval.h>
#include <assert.h>
#include <pthread.h>
#include "message_channel_internal.h"
#include "message_channel_base.h"

unsigned int message_channel_internal_hashfn(const void *_key)
{
    channel_key_t *key = (channel_key_t *)_key;
    unsigned long hash = init_name_hash();
    unsigned long len;
    const unsigned char *bits;

    len = sizeof(key->type);
    bits = (const unsigned char *)&key->type;

    while (len--)
        hash = partial_name_hash(*bits++, hash);

    len = sizeof(key->flags);
    bits = (const unsigned char *)&key->flags;

    while (len--)
        hash = partial_name_hash(*bits++, hash);

    len = sizeof(key->sock_type);
    bits = (const unsigned char *)&key->sock_type;

    while (len--)
        hash = partial_name_hash(*bits++, hash);

    len = sizeof(key->protocol);
    bits = (const unsigned char *)&key->protocol;

    while (len--)
        hash = partial_name_hash(*bits++, hash);
    
    if (key->local) {
        len = key->local_len;
        bits = (const unsigned char *)key->local;
        
        while (len--)
            hash = partial_name_hash(*bits++, hash);
    } 
    
    if (key->peer) {
        len = key->peer_len;
        bits = (const unsigned char *)key->peer;
        
        while (len--)
            hash = partial_name_hash(*bits++, hash);
    }
  
    return end_name_hash(hash);
}

void message_channel_internal_hold(message_channel_t *channel)
{
    hashelm_hold(&channel->he);
}

void message_channel_internal_put(message_channel_t *channel)
{
    hashelm_put(&channel->he);
}

message_channel_type_t 
message_channel_internal_get_type(struct message_channel *ch)
{
    return ch->type;
}

int message_channel_internal_register_callback(message_channel_t *channel,
                                               message_channel_callback_t *cb)
{
    int ret = -1;

    assert(channel);
    assert(cb);
    
    pthread_mutex_lock(&channel->lock);

    if (!channel->callback) {
        LOG_DBG("%s registered callback\n", channel->name);
        channel->callback = cb;
        ret = 0;
    }

    pthread_mutex_unlock(&channel->lock);

    return ret;
}

int message_channel_internal_unregister_callback(message_channel_t *channel,
                                                 message_channel_callback_t *cb)
{
    int ret = -1;

    assert(channel);
    assert(cb);

    pthread_mutex_lock(&channel->lock);
    
    if (channel->callback == cb) {
        channel->callback = NULL;
        ret = 0;
    }
    pthread_mutex_unlock(&channel->lock);

    return ret;
}

int message_channel_internal_get_callback_count(message_channel_t *channel)
{
    return channel->callback ? 1 : 0;
}

int message_channel_internal_on_start(message_channel_t *channel)
{
    if (channel->callback && channel->callback->start)
        return channel->callback->start(channel->callback);

    return 0;
}

void message_channel_internal_on_stop(message_channel_t *channel)
{
    if (channel->callback && channel->callback->stop)
        channel->callback->stop(channel->callback);
}

ssize_t message_channel_internal_recv_callback(message_channel_t *channel, struct message *msg)
{
    ssize_t ret = 0;

    if (!msg)
        return -1;

    if (channel->callback && channel->callback->recv) {
        ret = channel->callback->recv(channel->callback, msg);
    } else {
        LOG_DBG("%s has no registered callback\n", channel->name);
    }

    message_put(msg);

    return ret;
}
