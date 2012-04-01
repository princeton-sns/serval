/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Generic message channel API for passing Serval events.
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
#ifndef MESSAGE_CHANNEL_H_
#define MESSAGE_CHANNEL_H_

#include <common/atomic.h>
#include <common/list.h>
#include <common/debug.h>
#include <netinet/serval.h>
#include <sys/socket.h>
#if defined(OS_LINUX)
#include <linux/netlink.h>
#endif
#if defined(OS_UNIX)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif

struct message;

typedef union {
    struct sockaddr sa;
    struct sockaddr_sv sv;
#if defined(OS_UNIX)
    struct sockaddr_un un;
#endif
#if defined(OS_LINUX)
    struct sockaddr_nl nl;
#endif
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
    struct {
        struct sockaddr_sv sv;
        union {
            struct sockaddr_in in;
            struct sockaddr_in in6;
        };
    } sv_in;
} channel_addr_t;

#include "message.h"

typedef struct message_channel_callback {
    void *target;
    int (*start)(struct message_channel_callback *cb);
    void (*stop)(struct message_channel_callback *cb);
    int (*recv)(struct message_channel_callback *cb, 
                struct message *msg);
} message_channel_callback_t;

struct message_channel_ops;

typedef enum message_channel_type {
#if defined(OS_LINUX)
    MSG_CHANNEL_NETLINK,
#endif
#if defined(OS_UNIX)
    MSG_CHANNEL_UNIX,
#endif
    MSG_CHANNEL_UDP,
} message_channel_type_t;

struct message_channel;

struct message_channel *message_channel_get_generic(message_channel_type_t type,
                                                    int sock_type, int protocol,
                                                    const struct sockaddr *local,
                                                    socklen_t local_len,
                                                    const struct sockaddr *peer,
                                                    socklen_t peer_len,
                                                    int start);

struct message_channel *message_channel_get(message_channel_type_t type);

struct message_channel *message_channel_create(message_channel_type_t type);
message_channel_type_t message_channel_get_type(struct message_channel *ch);

int message_channel_register_callback(struct message_channel *channel,
                                      struct message_channel_callback *cb);
int message_channel_unregister_callback(struct message_channel *channel,
                                        struct message_channel_callback *cb);
int message_channel_get_callback_count(struct message_channel *channel);
int message_channel_get_local(struct message_channel *channel,
                              struct sockaddr *addr,
                              socklen_t *addrlen);
int message_channel_get_peer(struct message_channel *channel,
                             struct sockaddr *addr,
                             socklen_t *addrlen);
int message_channel_set_peer(struct message_channel *channel,
                             const struct sockaddr *addr, 
                             socklen_t len);
int message_channel_get_max_message_size(struct message_channel *channel);
void message_channel_hold(struct message_channel *channel);
void message_channel_put(struct message_channel *channel);

int message_channel_send(struct message_channel *channel,
                         void *msg, size_t msglen);
int message_channel_send_iov(struct message_channel *channel, 
                             struct iovec *iov,
                             size_t veclen, size_t length);

int message_channel_start(struct message_channel *channel);
void message_channel_stop(struct message_channel *channel);

#endif /* MESSAGE_CHANNEL_H_ */
