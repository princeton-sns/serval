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

int message_channel_internal_recv(message_channel_t *channel, const void *msg,
                                  size_t msglen, struct sockaddr *addr, 
                                  socklen_t addrlen)
{
    message_t *m = message_alloc(msg, msglen);
    int ret = 0;
    
    if (!m)
        return -1;

    /* Maybe figuring out the IP should be handled in the calling
       function instead? */
    if (addr->sa_family == AF_INET) {
        memcpy(&m->from, &((struct sockaddr_in *)addr)->sin_addr,
               sizeof(struct in_addr));
    } else if (addr->sa_family == AF_SERVAL && 
               addrlen > sizeof(struct sockaddr_sv)) {
        channel_addr_t *ca = (channel_addr_t *)addr;
        memcpy(&m->from, &ca->sv_in.in.sin_addr, sizeof(struct in_addr));
    }

    if (channel->callback) {
        ret = channel->callback->recv(channel->callback, m);
    } else {
        LOG_DBG("%s has no registered callback\n", channel->name);
    }

    message_put(m);

    return ret;
}
