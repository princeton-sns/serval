/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef MESSAGE_CHANNEL_INTERNAL_H_
#define MESSAGE_CHANNEL_INTERNAL_H_

#include <common/platform.h>
#include <common/hashtable.h>
#include <libservalctrl/message_channel.h>
#include <sys/types.h>
#include <pthread.h>

/* 
   Key used for hashing and argument passing.
*/
typedef struct channel_key_t {
    unsigned char type;
    unsigned char flags; /* Flags are channel specific. Used by, e.g.,
                          * UDP sub channel. */
    int sock_type;
    int protocol;
    const struct sockaddr *local;
    socklen_t local_len;
    const struct sockaddr *peer;
    socklen_t peer_len;
} channel_key_t;

enum channel_state {
    CHANNEL_CREATED = 0,
    CHANNEL_INITIALIZED,
    CHANNEL_RUNNING,
    CHANNEL_STOPPED,
    CHANNEL_DEAD,
};

typedef struct message_channel {
    unsigned char type;
    unsigned char flags;
    unsigned short state;
    pthread_mutex_t lock;
    const char *name;
    struct hashelm he;
    struct message_channel_ops *ops;
    message_channel_callback_t *callback;
} message_channel_t;

struct message;

typedef struct message_channel_ops {
    int (*equalfn)(const struct message_channel *channel, const void *key);
    unsigned int (*hashfn)(const void *key);
    int (*fillkey)(const struct message_channel *channel, void *key);
    int (*initialize) (struct message_channel *channel);
    int (*start) (struct message_channel *channel);
    void (*stop) (struct message_channel *channel);
    void (*finalize) (struct message_channel *channel);
    void (*hold)(struct message_channel *channel);
    void (*put)(struct message_channel *channel);
    
    int (*get_local) (struct message_channel *channel,
                      struct sockaddr *addr,
                      socklen_t *addrlen);
    int (*get_peer) (struct message_channel *channel,
                     struct sockaddr *addr,
                     socklen_t *addrlen);
    int (*set_peer) (struct message_channel *channel,
                     const struct sockaddr *addr, 
                     socklen_t len);
    int (*get_max_message_size) (struct message_channel *channel);

    /* for request/response callback handling */
    int (*register_callback) (struct message_channel *channel,
                              message_channel_callback_t *cb);
    int (*unregister_callback) (struct message_channel *channel,
                                message_channel_callback_t *cb);
    int (*get_callback_count) (struct message_channel *channel);
    
    int (*task)(struct message_channel *channel);
    int (*send)(struct message_channel *channel, void *message,
                size_t length);
    int (*send_iov)(struct message_channel *channel, struct iovec *iov,
                    size_t veclen, size_t length);
    ssize_t (*recv)(struct message_channel *channel, struct message **msg);
    ssize_t (*recv_callback)(struct message_channel *channel, struct message *msg);
} message_channel_ops_t;

typedef unsigned int (*channel_hashfn_t)(const void *key);
typedef int (*channel_equalfn_t)(const message_channel_t *c, const void *key);

int message_channel_libinit(void);
void message_channel_libfini(void);

int message_channel_init(message_channel_t *channel,
                         message_channel_type_t type, 
                         message_channel_ops_t *ops);
message_channel_t *message_channel_lookup(const void *key,
                                          channel_hashfn_t hashfn);
int message_channel_hash(message_channel_t *channel);
int message_channel_rehash(message_channel_t *channel);

unsigned int message_channel_internal_hashfn(const void *_key);
message_channel_type_t 
message_channel_internal_get_type(struct message_channel *ch);
void message_channel_internal_hold(message_channel_t *channel);
void message_channel_internal_put(message_channel_t *channel);
int message_channel_internal_register_callback(message_channel_t *channel,
                                      message_channel_callback_t *cb);
int message_channel_internal_unregister_callback(message_channel_t *channel,
                                        message_channel_callback_t *cb);
int message_channel_internal_get_callback_count(message_channel_t *channel);
ssize_t message_channel_internal_recv_callback(message_channel_t *channel, struct message *msg);
int message_channel_internal_on_start(message_channel_t *channel);
void message_channel_internal_on_stop(message_channel_t *channel);

#endif /* MESSAGE_CHANNEL_INTERNAL_H_ */
