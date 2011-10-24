/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef _REACTOR_INTERNAL_H_
#define _REACTOR_INTERNAL_H_

#include <common/timer.h>
#include <libservalctrl/task.h>
#include <libservalctrl/reactor.h>
#include <pthread.h>

enum reactor_retval {
    REACTOR_ERROR = -1,
    REACTOR_TIMEOUT = 0,
    REACTOR_TIMER_QUEUE,
    REACTOR_BLOCK_EVENT,
};

struct reactor_ops {
    int (*init)(struct reactor *r);
    void (*fini)(struct reactor *f);
	int (*wait)(struct reactor *r, const struct timespec *timeout);
};

struct reactor {
	struct timer_queue tq;
    struct list_head block_list;
    unsigned int num_blocks;
	pthread_mutex_t lock;
    int should_exit;
	struct reactor_ops *ops;
};

struct reactor *reactor_alloc(unsigned int size, struct reactor_ops *ops);
int reactor_init(struct reactor *r);
void reactor_fini(struct reactor *r);

#endif /* _REACTOR_INTERNAL_ */
