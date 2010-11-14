/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _TIMER_H_
#define _TIMER_H_

#if defined(__KERNEL__)
#include <linux/timer.h>
#else
#include "list.h"
#include <time.h>

struct timer_list {	
	struct list_head entry;
        struct timespec expires;
	struct tvec_base *base;
	void (*function)(unsigned long);
	unsigned long data;
};

#define TIMER_INITIALIZER(_function, _expires, _data) {		\
		.entry = { .prev = NULL, .next = NULL },        \
		.function = (_function),			\
		.expires = (_expires),				\
		.data = (_data),				\
	}

#define DEFINE_TIMER(_name, _function, _expires, _data)		\
	struct timer_list _name =				\
		TIMER_INITIALIZER(_function, _expires, _data)


static inline int timer_pending(const struct timer_list * timer)
{
	return timer->entry.next != NULL;
}
extern void add_timer(struct timer_list *timer);
extern int del_timer(struct timer_list * timer);
extern int mod_timer(struct timer_list *timer, unsigned long expires);
extern int mod_timer_pending(struct timer_list *timer, unsigned long expires);
extern int mod_timer_pinned(struct timer_list *timer, unsigned long expires);

#endif /* __KERNEL__ */

#endif /* _TIMER_H_ */
