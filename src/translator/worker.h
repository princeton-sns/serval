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
#ifndef __WORKER_H__
#define __WORKER_H__

#include <pthread.h>
#include <common/signal.h>
#include <common/list.h>
#if defined(OS_ANDROID)
#include "splice.h"
#define EPOLLRDHUP   (0x2000)
#define EPOLLONESHOT (1u << 30)
#endif

struct worker {
        unsigned int id;
        pthread_t thr;
        pthread_mutex_t lock; /* protects client list */
        int running;
        int epollfd;
        struct signal sig;
        unsigned int num_clients; /* num active clients */
        struct list_head new_clients;
        struct list_head active_clients;
        struct list_head garbage_clients;
};

int worker_start(struct worker *w);
int worker_init(struct worker *w, unsigned id);
int worker_add_client(struct worker *w, struct client *c);
void worker_destroy(struct worker *w);

#endif /* __WORKER_H__ */
