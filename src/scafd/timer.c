/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "timer.h"

static struct list_head timer_list = { &timer_list, &timer_list };
static pthread_mutex_t timer_lock = PTHREAD_MUTEX_INITIALIZER;

struct timer *timer_new_callback(int (*callback)(struct timer *), 
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

void timer_free(struct timer *t)
{
	free(t);
}

void timer_init(struct timer *t)
{
	memset(t, 0, sizeof(*t));
	INIT_LIST_HEAD(&t->lh);
}

int timer_add(struct timer *t)
{
	if (timer_scheduled(t))
		return -1;

	pthread_mutex_lock(&timer_lock);
        list_add_tail(&t->lh, &timer_list);
	pthread_mutex_unlock(&timer_lock);
	
	return 1;
}

void timer_del(struct timer *t)
{
	pthread_mutex_lock(&timer_lock);
	list_del(&t->lh);
	INIT_LIST_HEAD(&t->lh);
	pthread_mutex_unlock(&timer_lock);
}

int timer_next_timeout(unsigned long *timeout)
{
	struct timer *t;

	pthread_mutex_lock(&timer_lock);

	if (list_empty(&timer_list)) {
		pthread_mutex_unlock(&timer_lock);
		return 0;
	}
	
	t = list_first_entry(&timer_list, struct timer, lh);
	
	*timeout = t->expires;

	pthread_mutex_unlock(&timer_lock);

	return 1;
}

int timer_next_timeout_timeval(struct timeval *timeout)
{
	struct timer *t;

	pthread_mutex_lock(&timer_lock);

	if (list_empty(&timer_list)) {
		pthread_mutex_unlock(&timer_lock);
		return 0;
	}
	
	t = list_first_entry(&timer_list, struct timer, lh);
	
	timeout->tv_sec = t->expires / 1000000L;
	timeout->tv_usec = t->expires - (timeout->tv_sec * 1000000L);

	pthread_mutex_unlock(&timer_lock);

	return 1;
}

int timer_handle_timeout(void)
{
	struct timer *t;
	int ret = 0;
       
	pthread_mutex_lock(&timer_lock);

	if (list_empty(&timer_list)) {
		pthread_mutex_unlock(&timer_lock);
		return 0;
	}
	
	t = list_first_entry(&timer_list, struct timer, lh);
	list_del(&t->lh);
	INIT_LIST_HEAD(&t->lh);

	pthread_mutex_unlock(&timer_lock);

	if (t->callback)
		ret = t->callback(t);

	return ret;
}

void timer_list_destroy(void)
{
	pthread_mutex_lock(&timer_lock);

	while (1) {
		struct timer *t;
		
		if (list_empty(&timer_list))
			break;
		
		t = list_first_entry(&timer_list, struct timer, lh);
		list_del(&t->lh);
		timer_destroy(t);
	}
	pthread_mutex_unlock(&timer_lock);	
}
