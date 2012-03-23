/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Pipe-based IPC signals for waking/signaling between threads.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 *
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#ifndef __SIGNAL_H_
#define __SIGNAL_H_

#include "atomic.h"

typedef struct signal {
    int fd[2];
    atomic_t waiting; /* Incremented every time someone is waiting on
                         this signal */
} signal_t;

int signal_init(struct signal *s);
void signal_destroy(struct signal *s);
int signal_clear_val(struct signal *s, int *val);
int signal_clear(struct signal *s);
int signal_get_fd(struct signal *s);
int signal_is_raised(const struct signal *s);
int signal_wait_val(struct signal *s, int timeout, int *val);
int signal_wait(struct signal *s, int timeout);
int signal_raise_val(struct signal *s, int val);
int signal_raise(struct signal *s);
unsigned int signal_num_waiting(struct signal *s);

#endif /* __SIGNAL_H_ */
