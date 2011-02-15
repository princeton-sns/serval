/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _TIMER_H_
#define _TIMER_H_

#include <serval/platform.h>

#if defined(OS_LINUX_KERNEL)
#include <linux/timer.h>
#elif defined(OS_USER)
#include <serval/list.h>
#include <time.h>

#define CLOCK CLOCK_THREAD_CPUTIME_ID

/* #define PER_THREAD_TIMER_LIST 0 */

struct timer_list {	
	struct list_head entry;
        unsigned long expires;
	struct timespec expires_abs; /* For internal use, do not touch */
	void (*function)(unsigned long);
	unsigned long data;
};

#define TIMER_INITIALIZER(_name, _function, _expires, _data) {  \
		.entry = { NULL, NULL },                        \
		.function = (_function),			\
		.expires = (_expires),				\
                .expires_abs = { 0, 0 },                        \
		.data = (_data),				\
	}

#define DEFINE_TIMER(_name, _function, _expires, _data)		\
	struct timer_list _name =				\
		TIMER_INITIALIZER(_name, _function, _expires, _data)

/* User-level specific functions */

#if defined(PER_THREAD_TIMER_LIST)
int timer_list_per_thread_init(void);
#endif

int timer_list_signal_pending(void);
int timer_list_signal_lower(void);

int timer_list_get_next_timeout(struct timespec *, int signal[2]);
int timer_list_handle_timeout(void);

/* Kernel compatible API */
static inline int timer_pending(const struct timer_list *timer)
{
	return timer->entry.next != NULL;
}

void init_timer(struct timer_list *timer);
void add_timer(struct timer_list *timer);
int del_timer(struct timer_list * timer);
int mod_timer(struct timer_list *timer, unsigned long expires);
int mod_timer_pending(struct timer_list *timer, unsigned long expires);
int mod_timer_pinned(struct timer_list *timer, unsigned long expires);

static inline void setup_timer(struct timer_list *timer,
                               void (*function)(unsigned long),
                               unsigned long data)
{
	init_timer(timer);
	timer->function = function;
	timer->data = data;
}

unsigned long gettime_jiffies(void);
#define jiffies gettime_jiffies()

#define TICKS_PER_SEC 1000000000L
#define HZ (10000000L)
#define secs_to_jiffies(s) ((s * TICKS_PER_SEC) / HZ)
#define msecs_to_jiffies(ms) (ms / 10)
#define ticks_to_jiffies(t) (t / HZ)
#define nsecs_to_jiffies(ns) (ns / HZ)
#define jiffies_to_nsecs(j) (j * HZ)
#define timespec_to_jiffies(ts)                 \
        (secs_to_jiffies((ts)->tv_sec) +        \
         nsecs_to_jiffies((ts)->tv_usecs))

/* convenience functions (from RTLinux) */
#define NSECS_PER_SEC 1000000000L

#define timespec_normalize(t) {                         \
                if ((t)->tv_nsec >= NSECS_PER_SEC) {    \
                        (t)->tv_nsec -= NSECS_PER_SEC;  \
                        (t)->tv_sec++;                  \
                } else if ((t)->tv_nsec < 0) {          \
                        (t)->tv_nsec += NSECS_PER_SEC;  \
                        (t)->tv_sec--;                  \
                }                                       \
        }

#define timespec_add_nsec(t1, nsec) do {                                \
                unsigned long secs = nsec / NSECS_PER_SEC;              \
                (t1)->tv_sec += secs;                                   \
                (t1)->tv_nsec += (nsec - (secs * NSECS_PER_SEC));       \
                timespec_normalize(t1);                                 \
        } while (0)

#define timespec_add(t1, t2) do {               \
                (t1)->tv_nsec += (t2)->tv_nsec; \
                (t1)->tv_sec += (t2)->tv_sec;   \
                timespec_normalize(t1);         \
        } while (0)

#define timespec_sub(t1, t2) do {               \
                (t1)->tv_nsec -= (t2)->tv_nsec; \
                (t1)->tv_sec -= (t2)->tv_sec;   \
                timespec_normalize(t1);         \
        } while (0)

#define timespec_nz(t) ((t)->tv_sec != 0 || (t)->tv_nsec != 0)
#define timespec_lt(t1, t2) ((t1)->tv_sec < (t2)->tv_sec || \
                             ((t1)->tv_sec == (t2)->tv_sec && \
                              (t1)->tv_nsec < (t2)->tv_nsec))
#define timespec_gt(t1, t2) (timespec_lt(t2, t1))
#define timespec_ge(t1, t2) (!timespec_lt(t1, t2))
#define timespec_le(t1, t2) (!timespec_gt(t1, t2))
#define timespec_eq(t1, t2) ((t1)->tv_sec == (t2)->tv_sec && \
                             (t1)->tv_nsec == (t2)->tv_nsec)

#endif /* OS_LINUX_KERNEL */

#endif /* _TIMER_H_ */
