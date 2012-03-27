/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <common/list.h>
#include <common/hash.h>
#include <common/hashtable.h>
#include <netinet/in.h>
#include <netinet/serval.h>
#include <assert.h>
#include <pthread.h>
#include <libservalctrl/message_channel.h>
#include "message_channel_internal.h"
#include "message_channel_base.h"

#if defined(OS_LINUX)
extern message_channel_t *message_channel_netlink_create(channel_key_t *);
#endif
extern message_channel_t *message_channel_udp_create(channel_key_t *);
#if defined(OS_UNIX)
extern message_channel_t *message_channel_unix_create(channel_key_t *);
#endif

typedef message_channel_t *(*message_channel_constructor_t)(channel_key_t *);

static message_channel_constructor_t channel_constructor[] = {
#if defined(OS_LINUX)
    [ MSG_CHANNEL_NETLINK ] = message_channel_netlink_create,
#endif
#if defined(OS_UNIX)
    [ MSG_CHANNEL_UNIX ] = message_channel_unix_create,
#endif
    [ MSG_CHANNEL_UDP ] = message_channel_udp_create,
};

static char *channel_name[] = {
#if defined(OS_LINUX)
    [ MSG_CHANNEL_NETLINK ] = "NETLINK",
#endif
#if defined(OS_UNIX)
    [ MSG_CHANNEL_UNIX ] = "UNIX",
#endif
    [ MSG_CHANNEL_UDP ] = "UDP",
};

#if defined(OS_LINUX)
extern message_channel_ops_t netlink_ops;
#endif
#if defined(OS_UNIX)
extern message_channel_ops_t unix_ops;
#endif
extern message_channel_ops_t udp_ops;

static message_channel_ops_t *channel_ops[] = {
#if defined(OS_LINUX)
    [ MSG_CHANNEL_NETLINK ] = &netlink_ops,
#endif
#if defined(OS_UNIX)
    [ MSG_CHANNEL_UNIX ] = &unix_ops,
#endif
    [ MSG_CHANNEL_UDP ] = &udp_ops,  
};

static hashtable_t channel_table;

/*
  Hash table initialization. Called once, at startup.
*/

int message_channel_libinit(void)
{
    return hashtable_init(&channel_table, HTABLE_MIN_SIZE);
}

/*
static void channel_stop(struct hashelm *elm)
{
    struct message_channel *c = container_of(elm, struct message_channel, he);
    c->ops->stop(c);
}
*/

void message_channel_libfini(void)
{
    /* LOG_DBG("libfini\n");
       hashtable_for_each(&channel_table, channel_stop);
       hashtable_fini(&channel_table); */
}

static inline int equal_wrapper(const struct hashelm *elm, const void *key)
{
    struct message_channel *c = container_of(elm, struct message_channel, he);
    return c->ops->equalfn(c, key);
}

static inline void free_wrapper(struct hashelm *elm)
{
    struct message_channel *c = container_of(elm, struct message_channel, he);
    c->ops->finalize(c);
    pthread_mutex_destroy(&c->lock);
    free(c);
}

int message_channel_init(message_channel_t *channel, 
                         message_channel_type_t type, 
                         message_channel_ops_t *ops)
{
    channel->state = CHANNEL_CREATED;
    channel->type = type;
    channel->ops = ops;
    pthread_mutex_init(&channel->lock, NULL);

    return hashelm_init(&channel->he, ops->hashfn, equal_wrapper, 
                        free_wrapper);
}

static int message_channel_hashed(message_channel_t *channel)
{
    return hashelm_hashed(&channel->he);
}

int message_channel_hash(message_channel_t *channel)
{
    channel_key_t key;
    channel->ops->fillkey(channel, &key);
    return hashelm_hash(&channel_table, &channel->he, &key);
}

static void message_channel_unhash(message_channel_t *channel)
{
    hashelm_unhash(&channel_table, &channel->he);
}

int message_channel_rehash(message_channel_t *channel)
{
    message_channel_unhash(channel);
    return message_channel_hash(channel);
}

message_channel_t *message_channel_lookup(const void *key,
                                          channel_hashfn_t hashfn)
{
    hashelm_t *e;

    e = hashtable_lookup(&channel_table, key, hashfn);

    if (!e)
        return NULL;

    return container_of(e, struct message_channel, he);
}

message_channel_t *message_channel_get_generic(message_channel_type_t type,
                                               int sock_type,
                                               int protocol,
                                               const struct sockaddr *local,
                                               socklen_t local_len,
                                               const struct sockaddr *peer,
                                               socklen_t peer_len,
                                               int start)
{
    message_channel_t *c;
    channel_key_t key = { type, 0, sock_type, protocol, 
                          local, local_len, peer, peer_len };
    
    c = message_channel_lookup(&key, channel_ops[type]->hashfn);
    
    if (!c) {
        c = channel_constructor[type](&key);
        
        if (!c)
            return NULL;

        c->name = channel_name[type];

        if (c->ops->initialize(c)) {
            LOG_ERR("Channel initialization failed\n");
            goto failure;
        }
        
        if (start && message_channel_start(c)) {
            LOG_ERR("Channel startup failed\n");
            goto failure;           
        }
    }
    
    return c;
failure:
    c->ops->put(c);
    return NULL;
}

message_channel_t *message_channel_get(message_channel_type_t type)
{
    return message_channel_get_generic(type, 0, 0, NULL, 0, NULL, 0, 1);
}

/* 
   The following functions are mostly just wrappers around the
   "overridable" functions in the message channel interface. The
   default interface implementations are in
   message_channel_internal.c
 */
   
void message_channel_hold(message_channel_t *channel)
{
    /*
    LOG_DBG("%s refcount is %u\n", 
            channel->name,
            atomic_read(&channel->he.refcount) + 1);
    */
    return channel->ops->hold(channel);
}

void message_channel_put(message_channel_t *channel)
{
    /*
    LOG_DBG("%s refcount is %u\n", 
            channel->name,
            atomic_read(&channel->he.refcount) - 1);
    */
    return channel->ops->put(channel);
}

message_channel_type_t message_channel_get_type(struct message_channel *ch)
{
    return ch->type;
}

int message_channel_register_callback(message_channel_t *channel,
                                      message_channel_callback_t *cb)
{
    if (channel->state != CHANNEL_RUNNING)
        return channel->ops->register_callback(channel, cb);

    LOG_ERR("%s trying to register callback on running channel\n",
            channel->name);
    return -1;
}

int message_channel_unregister_callback(message_channel_t *channel,
                                        message_channel_callback_t *cb)
{
    if (channel->state != CHANNEL_RUNNING)
        return channel->ops->unregister_callback(channel, cb);

    LOG_ERR("%s trying to unregister callback on running channel\n",
            channel->name);

    return -1;
}

int message_channel_get_callback_count(message_channel_t *channel)
{
      return channel->ops->get_callback_count(channel);
}

int message_channel_get_local(struct message_channel *channel,
                              struct sockaddr *addr,
                              socklen_t *addrlen)
{
    return channel->ops->get_local(channel, addr, addrlen);
}

int message_channel_get_peer(struct message_channel *channel,
                             struct sockaddr *addr,
                             socklen_t *addrlen)
{
    return channel->ops->get_peer(channel, addr, addrlen);
}

int message_channel_set_peer(struct message_channel *channel,
                             const struct sockaddr *addr, 
                             socklen_t len)
{
    return channel->ops->set_peer(channel, addr, len);
}

int message_channel_get_max_message_size(struct message_channel *channel)
{
    if (channel->ops->get_max_message_size)
        return channel->ops->get_max_message_size(channel);
    return 0;
}

int message_channel_send_iov(message_channel_t *channel, struct iovec * iov,
                             size_t veclen, size_t length)
{
    return channel->ops->send_iov(channel, iov, veclen, length);
}

int message_channel_send(message_channel_t *channel, 
                         void *msg, size_t msglen)
{
    return channel->ops->send(channel, msg, msglen);
}

int message_channel_start(message_channel_t *channel)
{
    int ret = channel->ops->start(channel);
 
    if (ret == 0 && !message_channel_hashed(channel))
        message_channel_hash(channel);

    return ret;
}

void message_channel_stop(message_channel_t *channel)
{
    LOG_DBG("Stopping channel %s\n", channel->name);
    channel->ops->stop(channel);
    LOG_DBG("Stopped channel %s\n", channel->name);
    message_channel_unhash(channel);
}
