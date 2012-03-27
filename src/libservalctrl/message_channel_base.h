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
#ifndef MESSAGE_CHANNEL_BASE_H_
#define MESSAGE_CHANNEL_BASE_H_

#include <common/platform.h>
#include <common/signal.h>
#include <libservalctrl/message_channel.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <poll.h>
#if defined(OS_LINUX)
#include <linux/netlink.h>
#endif
#include <netinet/serval.h>

#define RECV_BUFFER_SIZE 2048

typedef struct message_channel_base {
    struct message_channel channel;
    int sock;
    int sock_type;
    int protocol;
    short running;
    short should_join;
    int native_socket;
    channel_addr_t local;
    socklen_t local_len;
    channel_addr_t peer;
    socklen_t peer_len;
    struct signal exit_signal;
    pthread_t thread;
} message_channel_base_t;

#define MAX_SEND_RETRIES 10

message_channel_t *message_channel_base_create(channel_key_t *key,
                                               size_t size,
                                               message_channel_ops_t *ops);
int message_channel_base_init(message_channel_base_t *base,
                              message_channel_type_t type, 
                              int sock_type,
                              int protocol,
                              const struct sockaddr *local,
                              socklen_t local_len,
                              const struct sockaddr *peer,
                              socklen_t peer_len,
                              message_channel_ops_t *ops);
int message_channel_base_equalfn(const message_channel_t *channel, const void *_key);
int message_channel_base_fillkey(const message_channel_t *channel, void *_key);
int message_channel_base_initialize(message_channel_t *channel);
void message_channel_base_finalize(message_channel_t *channel);
int message_channel_base_start(message_channel_t *channel);
void message_channel_base_stop(message_channel_t *channel);
int message_channel_base_get_local(message_channel_t *channel,
                                   struct sockaddr *addr,
                                   socklen_t *addrlen);
int message_channel_base_get_peer(message_channel_t *channel,
                                  struct sockaddr *addr,
                                  socklen_t *addrlen);
int message_channel_base_set_peer(message_channel_t *channel, 
                                  const struct sockaddr *addr, socklen_t len);
int message_channel_base_send_iov(message_channel_t *channel, struct iovec *iov,
                                  size_t veclen, size_t msglen);
int message_channel_base_send(message_channel_t *channel, 
                              void *msg, size_t msglen);
ssize_t message_channel_base_recv(struct message_channel *channel, 
                                  struct message **msg);
int message_channel_base_task(struct message_channel *channel);

#endif /* MESSAGE_CHANNEL_BASE_H_ */
