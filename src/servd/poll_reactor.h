/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * SelectContext.h
 *
 *  Created on: Oct 25, 2009
 *      Author: daveds
 */

#ifndef _POLLREACTOR_H_
#define _POLLREACTOR_H_

//#include "fd_exec_list.hh"
#include "time_util.h"
#include "debug.h"
#include "task.h"

#include <pthread.h>
#include <glib.h>

#define DEFAULT_POLL_TIMEOUT 5
#define MAX_POLL_EVENTS 256

typedef void (*reactor_exec) (void *target);

enum reactor_state {
    REACTOR_CREATED = 0, REACTOR_INITIALIZED = 1, REACTOR_STARTED =
	2, REACTOR_STOPPED = 3
};

/*
 * Encapsulates the main select run loop and file descriptor sets for async methods
 * to signal their interest in read/write/error conditions
 */

typedef struct poll_reactor_ds {

    //executes a given context to completion
    GHashTable *task_map;
    GSequence *timeout_seq;

    uint16_t state;
    time_t default_timeout;
    long long current_timeout;

    int read_count;
    int write_count;
    int error_count;

    int poll_fd;
    int max_events;

    int threaded;
    task_handle_t poll_task;
    pthread_mutex_t mutex;
} poll_reactor;

#define POLL_REACTOR_INIT { NULL, NULL,REACTOR_CREATED,DEFAULT_POLL_TIMEOUT, 0,0,0,0,0,MAX_POLL_EVENTS,0,0,PTHREAD_MUTEX_INITIALIZER }

void pr_set_read(struct poll_reactor_ds *, int fd, reactor_exec exec,
		 void *data);
void pr_set_write(struct poll_reactor_ds *, int fd, reactor_exec exec,
		  void *data);
void pr_set_error(struct poll_reactor_ds *, int fd, reactor_exec exec,
		  void *data);
void pr_set_interest(struct poll_reactor_ds *, int fd, reactor_exec rexec,
		     void *rdata, reactor_exec wexec, void *wdata,
		     reactor_exec eexec, void *edata);

void *pr_clear_read(struct poll_reactor_ds *, int fd);
void *pr_clear_write(struct poll_reactor_ds *, int fd);
void *pr_clear_error(struct poll_reactor_ds *, int fd);
void *pr_clear_interest(struct poll_reactor_ds *, int fd);

void pr_clear_task(struct poll_reactor_ds *, reactor_exec exec, void *data);
void pr_clear(struct poll_reactor_ds *);

int pr_initialize(struct poll_reactor_ds *);
int pr_finalize(struct poll_reactor_ds *);
void pr_start(struct poll_reactor_ds *);
void pr_stop(struct poll_reactor_ds *);

void pr_add_timeout(struct poll_reactor_ds *, time_t msec,
		    reactor_exec exec, void *data);
int pr_cancel_timeout(struct poll_reactor_ds *, reactor_exec exec, void *data);
int pr_is_waiting(struct poll_reactor_ds *, reactor_exec exec, void *data);

#endif				/* _POLLREACTOR_H_ */
