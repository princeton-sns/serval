/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _TIMER_H_
#define _TIMER_H_

#include <serval/list.h>
#include <sys/types.h>
#include <sys/time.h>

struct timer {
        struct list_head lh;
        struct timeval timeout;
        unsigned long expires; /* Micro seconds */
        int (*callback)(struct timer *t);
        void (*destruct)(struct timer *t);
        void *data;        
};

#define TIMER_CALLBACK(t, cb) struct timer t = {       \
                .lh = { &t.lh, &t.lh }, \
                .expires = 0, \
                .callback = cb, \
                .destruct = NULL, \
                .data = NULL \
        }
#define TIMER(t) TIMER_CALLBACK(t, NULL)

void timer_init(struct timer *t);
struct timer *timer_new_callback(int (*callback)(struct timer *t), void *data);
void timer_free(struct timer *t);
int timer_add(struct timer *t);
void timer_del(struct timer *t);
int timer_next_timeout(unsigned long *timeout);
int timer_next_timeout_timeval(struct timeval *timeout);
int timer_handle_timeout(void);
void timer_list_destroy(void);

#define timer_new() timer_new_callback(NULL, NULL)
#define timer_set_secs(t, s) { (t)->expires = s * 1000000L; }
#define timer_set_msecs(t, s) { (t)->expires = s * 1000L; }
#define timer_schedule_secs(t, s) ({ int ret;   \
                timer_set_secs(t, s); \
                ret = timer_add(t); \
                ret; })
#define timer_schedule_msecs(t, s) ({ int ret; \
                timer_set_msecs(t, s); \
                ret = timer_add(t); \
                ret; })
#define timer_scheduled(t) !list_empty(&t->lh)
#define timer_destroy(t) { if ((t)->destruct) (t)->destruct(t); }

#endif /* _TIMER_H_ */
