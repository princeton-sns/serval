/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- 
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#ifndef __CLIENT_H__
#define __CLIENT_H__

#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/serval.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <common/list.h>

struct client;
struct worker;

typedef union sockaddr_generic {
        struct sockaddr sa;
        struct sockaddr_sv sv;
        struct sockaddr_in in;
        struct {
                struct sockaddr_sv sv;
                struct sockaddr_in in;
        } sv_in;
} sockaddr_generic_t;

enum socket_state {
        SS_INIT,
        SS_CONNECTING,
        SS_CONNECTED,
        SS_CLOSED,
};

#if defined(ENABLE_DEBUG)
extern const char *socket_state_str[];
#endif

struct socket {
        int fd; /* Must be first */
        int splicefd[2];
        enum socket_state state;
        struct client *c;
        uint32_t monitored_events;
        uint32_t active_events;
        sockaddr_generic_t addr;
        socklen_t addrlen;
        size_t bytes_in_pipe, bytes_written, bytes_read;
        socklen_t sndbuf;
};

enum sockettype {
        ST_INET,
        ST_SERVAL,
};

enum work_status {
        WORK_OK,
        WORK_CLOSE,
        WORK_EXIT,
        WORK_WOULDBLOCK,
        WORK_ERROR,
};

typedef enum work_status (*work_t)(struct client *c);

#define MAX_WORK 4

struct client {
        int from_family;
        unsigned int id;
        struct socket sock[2];
        int translator_port;
        struct worker *w;
        unsigned int num_work;
        work_t work[MAX_WORK];
        unsigned char cross_translate:1;
        unsigned char is_garbage:1;
        struct list_head lh;
};

struct client *client_create(int sock, struct sockaddr *sa, 
                             socklen_t salen, int cross_translate);
int client_epoll_set(struct client *c, struct socket *s, 
		       int op, unsigned int extra_event);
int client_epoll_set_all(struct client *c, int op, 
                         unsigned int extra_event);
int client_add_work(struct client *c, work_t work);
enum work_status client_close(struct client *c);
void client_assign_worker(struct client *c);
void client_free(struct client *c);
enum work_status client_connect(struct client *c);
enum work_status client_connect_result(struct client *c);
void socket_close(struct socket *s);

#endif /* __CLIENT_H__ */
