/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- 
 *
 * A timer queue that can integrate with, e.g., select/poll loops.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <poll.h>
#include <common/timer.h>
#include <common/debug.h>
#include <time.h>

#define CLOCK CLOCK_THREAD_CPUTIME_ID

static int gettime(struct timespec *ts)
{
    int err = 0;

#if _POSIX_TIMERS > 0
    err = clock_gettime(CLOCK, ts);

	if (err == -1) {
		LOG_ERR("clock_gettime failed: %s\n", 
                strerror(errno));
	}
#else
    struct timeval now;

    gettimeofday(&now, NULL);

    ts->tv_sec = now.tv_sec;
    ts->tv_nsec = now.tv_usec * 1000;
#endif
    return err;
}

static int heap_cmp(const struct heapitem *h1, const struct heapitem *h2)
{
    struct timer *t1 = heap_entry(h1, struct timer, hi); 
    struct timer *t2 = heap_entry(h2, struct timer, hi); 

    return timespec_lt(&t1->timeout, &t2->timeout);
}

struct timer *timer_new_callback(void (*callback)(struct timer *), 
                                 void *data)
{
	struct timer *t = malloc(sizeof(struct timer));

	if (!t)
		return NULL;

	timer_init(t);
	t->callback = callback;
	t->data = data;
	
	return t;
}

int timer_queue_get_signal(struct timer_queue *tq)
{
    return signal_get_fd(&tq->signal);
}

int timer_queue_signal_raise(struct timer_queue *tq)
{
    return signal_raise(&tq->signal);
}

enum signal_result timer_queue_signal_lower(struct timer_queue *tq)
{
    int val = 0, ret = 0;
    
    ret = signal_clear_val(&tq->signal, &val);

    switch (ret) {
    case -1:
        ret = TIMER_SIGNAL_ERROR;
        break;
    case 0:
        ret = TIMER_SIGNAL_NONE;
        break;
    default:
        if (val == 0)
            ret = TIMER_SIGNAL_EXIT;
        else if (val == -1)
            ret = TIMER_SIGNAL_ERROR;
        else 
            ret = TIMER_SIGNAL_SET;
                
    }
    return (enum signal_result)ret;
}

void timer_free(struct timer *t)
{
	free(t);
}

void timer_init(struct timer *t)
{
	memset(t, 0, sizeof(*t));
}

int timer_mod(struct timer_queue *tq, struct timer *t, 
              unsigned long expires)
{
    int was_first = 0;

    if (timer_scheduled(t)) {
        if (t->hi.index == 0)
            was_first = 1;
        timer_del(tq, t);
        t->expires = expires;
    }

    gettime(&t->timeout);
    timespec_add_nsec(&t->timeout, t->expires * 1000);

	pthread_mutex_lock(&tq->lock);

    if (heap_insert(&tq->queue, &t->hi)) {
        pthread_mutex_unlock(&tq->lock);
        return -1;
    }

    /* If another thread than the "main" thread added or removed a
     * timer at the first position in the heap, then raise the signal
     * to make the main thread reschedule itself to reflect the new
     * timeout */
    if (!pthread_equal(tq->thr, pthread_self()) &&
        (t->hi.index == 0 || was_first == 1)) {
        timer_queue_signal_raise(tq);
    }
    
	pthread_mutex_unlock(&tq->lock);
	
	return 1;
}


static void _timer_del(struct timer_queue *tq, struct timer *t)
{
    unsigned int index = t->hi.index;

    heap_remove(&tq->queue, index);

    /* Reschedule in case we removed the first item in the
       queue */
    if (index == 0 && !pthread_equal(tq->thr, pthread_self()))
        timer_queue_signal_raise(tq);
}

int timer_add(struct timer_queue *tq, struct timer *t)
{
	if (timer_scheduled(t))
		return -1;

    return timer_mod(tq, t, t->expires);
}

void timer_del(struct timer_queue *tq, struct timer *t)
{
	pthread_mutex_lock(&tq->lock);
    _timer_del(tq, t);
	pthread_mutex_unlock(&tq->lock);
}

int timer_next_timeout(struct timer_queue *tq, unsigned long *timeout)
{
	struct timer *t;
    struct timespec now, later;

	pthread_mutex_lock(&tq->lock);

	if (heap_empty(&tq->queue)) {
		pthread_mutex_unlock(&tq->lock);
        timer_queue_signal_lower(tq);
		return 0;
	}

    gettime(&now);

	t = heap_first_entry(&tq->queue, struct timer, hi);       
    memcpy(&later, &t->timeout, sizeof(t->timeout));
    timespec_sub(&later, &now);
	*timeout = later.tv_sec * 1000000 + later.tv_nsec / 1000;

	pthread_mutex_unlock(&tq->lock);

    timer_queue_signal_lower(tq);

	return 1;
}

int timer_next_timeout_timespec(struct timer_queue *tq, 
                                struct timespec *timeout)
{
	struct timer *t;
    struct timespec now;

	pthread_mutex_lock(&tq->lock);

	if (heap_empty(&tq->queue)) {
		pthread_mutex_unlock(&tq->lock);
		return 0;
	}

    gettime(&now);

	t = heap_first_entry(&tq->queue, struct timer, hi);
	memcpy(timeout, &t->timeout, sizeof(*timeout));
    timespec_sub(timeout, &now);
        
    if (timeout->tv_sec < 0)
        timeout->tv_sec = timeout->tv_nsec = 0;
                
	pthread_mutex_unlock(&tq->lock);

	return 1;
}

int timer_next_timeout_timeval(struct timer_queue *tq, 
                               struct timeval *timeout)
{
    struct timespec ts;
    int ret;
        
    ret = timer_next_timeout_timespec(tq, &ts);

    timeout->tv_sec = ts.tv_sec;
    timeout->tv_usec = ts.tv_nsec / 1000;
        
    return ret;
}

int timer_handle_timeout(struct timer_queue *tq)
{
	struct timer *t;
       
	pthread_mutex_lock(&tq->lock);

	if (heap_empty(&tq->queue)) {
		pthread_mutex_unlock(&tq->lock);
		return -1;
	}
	
	t = heap_remove_first_entry(&tq->queue, struct timer, hi);

	pthread_mutex_unlock(&tq->lock);

	if (t->callback)
        t->callback(t);

    return 0;
}

void timer_list_destroy(struct timer_queue *tq)
{
	pthread_mutex_lock(&tq->lock);

	while (1) {
		struct timer *t;
		
		if (heap_empty(&tq->queue))
			break;
		
		t = heap_remove_first_entry(&tq->queue, struct timer, hi);

		if (t->destruct)
            t->destruct(t);
    }
	pthread_mutex_unlock(&tq->lock);	
}

int timer_queue_init(struct timer_queue *tq)
{
    int ret;

    memset(tq, 0, sizeof(*tq));

    ret = signal_init(&tq->signal);

    if (ret == -1) {
        LOG_ERR("Signal init failed\n");
    }

    heap_init(&tq->queue, 0, heap_cmp);

    tq->thr = pthread_self();

    return ret;
}

void timer_queue_fini(struct timer_queue *tq)
{
    signal_destroy(&tq->signal);
    timer_list_destroy(tq);
    heap_fini(&tq->queue);
}
