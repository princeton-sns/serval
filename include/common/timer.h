/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Timer queue implementation that integrates with select/poll loops.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 *
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#ifndef _TIMER_H_
#define _TIMER_H_

#include <sys/types.h>
#include <sys/time.h>
#include <pthread.h>
#include "heap.h"
#include "signal.h"

struct timer {
    struct heapitem hi;
    struct timespec timeout;
    long expires; /* micro seconds */
    void (*callback)(struct timer *t);
    void (*destruct)(struct timer *t);
    void *data;        
};

struct timer_queue {
    struct heap queue;
    pthread_mutex_t lock;
    struct signal signal;
    pthread_t thr;
};

#define TIMER_CALLBACK(t, cb) struct timer t = {    \
        .lh = { &t.lh, &t.lh },                     \
        .expires = 0,                               \
        .callback = cb,                             \
        .destruct = NULL,                           \
        .data = NULL                                \
    }
#define TIMER(t) TIMER_CALLBACK(t, NULL)

enum signal_result {
    TIMER_SIGNAL_ERROR = -1,
    TIMER_SIGNAL_NONE,
    TIMER_SIGNAL_SET,
    TIMER_SIGNAL_EXIT,
};

void timer_init(struct timer *t);
struct timer *timer_new_callback(void (*callback)(struct timer *t), void *data);
void timer_free(struct timer *t);
int timer_add(struct timer_queue *tq, struct timer *t);
int timer_mod(struct timer_queue *tq, struct timer *t, unsigned long expires);
void timer_del(struct timer_queue *tq, struct timer *t);
int timer_next_timeout(struct timer_queue *tq, unsigned long *timeout);
int timer_next_timeout_timespec(struct timer_queue *tq, 
                                struct timespec *timeout);
int timer_next_timeout_timeval(struct timer_queue *tq, 
                               struct timeval *timeout);
int timer_handle_timeout(struct timer_queue *tq);
int timer_queue_get_signal(struct timer_queue *tq);
int timer_queue_signal_raise(struct timer_queue *tq);
enum signal_result timer_queue_signal_lower(struct timer_queue *tq);
void timer_queue_destroy(struct timer_queue *tq);
int timer_queue_init(struct timer_queue *tq);
void timer_queue_fini(struct timer_queue *tq);

#define timer_new() timer_new_callback(NULL, NULL
#define timer_secs(s) (s * 1000000L)
#define timer_msecs(s) (s * 1000L)
#define timer_usecs(s) (s)
#define timer_set_secs(t, s) { (t)->expires = timer_secs(s); }
#define timer_set_msecs(t, s) { (t)->expires = timer_msecs(s); }
#define timer_set_usecs(t, s) { (t)->expires = s; }
#define timer_schedule_secs(tq, t, s) ({ int ret;   \
            timer_set_secs(t, s);                   \
            ret = timer_add(tq, t);                 \
            ret; })
#define timer_schedule_msecs(tq, t, s) ({ int ret;  \
            timer_set_msecs(t, s);                  \
            ret = timer_add(tq, t);                 \
            ret; })
#define timer_scheduled(t) (t->hi.active)
#define timer_destroy(t) { if ((t)->destruct) (t)->destruct(t); }

/* convenience functions (from RTLinux) */
#define NSEC_PER_SEC   1000000000L
#define NSEC_PER_MSEC  1000000L
#define USEC_PER_SEC   1000000L
#define MSEC_PER_SEC   1000L
#define NSEC_PER_USEC  1000L
#define USEC_PER_MSEC  1000L

#define timespec_normalize(t) {                 \
        if ((t)->tv_nsec >= NSEC_PER_SEC) {     \
            (t)->tv_nsec -= NSEC_PER_SEC;       \
            (t)->tv_sec++;                      \
        } else if ((t)->tv_nsec < 0) {          \
            (t)->tv_nsec += NSEC_PER_SEC;       \
            (t)->tv_sec--;                      \
        }                                       \
    }

#define timespec_add_nsec(t1, nsec) do {        \
        (t1)->tv_sec += nsec / NSEC_PER_SEC;    \
        (t1)->tv_nsec += nsec % NSEC_PER_SEC;   \
        timespec_normalize(t1);                 \
    } while (0)

#define timespec_add(t1, t2) do {               \
        (t1)->tv_nsec += (t2)->tv_nsec;         \
        (t1)->tv_sec += (t2)->tv_sec;           \
        timespec_normalize(t1);                 \
    } while (0)

#define timespec_sub(t1, t2) do {               \
        (t1)->tv_nsec -= (t2)->tv_nsec;         \
        (t1)->tv_sec -= (t2)->tv_sec;           \
        timespec_normalize(t1);                 \
    } while (0)

#define timespec_nz(t) ((t)->tv_sec != 0 || (t)->tv_nsec != 0)
#define timespec_lt(t1, t2) ((t1)->tv_sec < (t2)->tv_sec ||     \
                             ((t1)->tv_sec == (t2)->tv_sec &&   \
                              (t1)->tv_nsec < (t2)->tv_nsec))
#define timespec_gt(t1, t2) (timespec_lt(t2, t1))
#define timespec_ge(t1, t2) (!timespec_lt(t1, t2))
#define timespec_le(t1, t2) (!timespec_gt(t1, t2))
#define timespec_eq(t1, t2) ((t1)->tv_sec == (t2)->tv_sec &&    \
                             (t1)->tv_nsec == (t2)->tv_nsec)

#endif /* _TIMER_H_ */
