/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef _REACTOR_H_
#define _REACTOR_H_

#include <common/list.h>
#include <common/timer.h>

enum reactor_event {
    RF_READ = (1 << 0),
    RF_WRITE = (1 << 1),
    RF_ERROR = (1 << 2),
    RF_ALL = (0xff << 2),
};

struct reactor_block {
	struct timer timer;
    struct list_head block_node;
    struct list_head callback_node;
    int cancel;
	unsigned short events;
	unsigned short revents;
	int fd;
    void *data;
    void (*callback)(void *data);
};

struct reactor;

struct reactor *reactor_create(void);
void reactor_stop(struct reactor *r);
void reactor_free(struct reactor *r);
int reactor_add(struct reactor *r, struct reactor_block *rb);
void reactor_remove(struct reactor *r, struct reactor_block *rb);
void reactor_loop(void *data);
int reactor_block_init(struct reactor_block *rb,
                       int fd, unsigned short flags,
                       void (*callback)(void *data),
                       void *data, long ms_timeout);

#endif /* _REACTOR_H_ */
