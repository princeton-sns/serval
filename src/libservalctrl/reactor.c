/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <common/timer.h>
#include <common/debug.h>
#include <libservalctrl/task.h>
#include <libservalctrl/reactor.h>
#include "reactor_internal.h"

int reactor_add(struct reactor *r, struct reactor_block *rb)
{
    pthread_mutex_lock(&r->lock);

    list_add_tail(&rb->block_node, &r->block_list);
    r->num_blocks++;

    pthread_mutex_unlock(&r->lock);

    /* Add timer in case there is a valid timeout */
    if (rb->timer.expires >= 0) {
        timer_add(&r->tq, &rb->timer);
    }
    /* Force the timer queue's rescheduling signal to be raised, even
     * though we might not have added a new timer to the queue. The
     * reason is that we use this signal to also reschedule the wait
     * call in the reactor_loop when we add a new reactor block */
    if (rb->fd > 0)
        timer_queue_signal_raise(&r->tq);

    LOG_DBG("Added reactor block fd=%d to reactor\n", rb->fd);

    return 0;
}

void reactor_remove(struct reactor *r, struct reactor_block *rb)
{
    pthread_mutex_lock(&r->lock);

    if (list_empty(&rb->block_node)) {
        LOG_DBG("reactor block fd=%d not watched\n", rb->fd);
        pthread_mutex_unlock(&r->lock);
        return;
    }

    rb->cancel = 1;
    /*
    list_del(&rb->block_node);
    INIT_LIST_HEAD(&rb->block_node);
    r->num_blocks--;
    */
    LOG_DBG("Removed reactor block fd=%d\n", rb->fd);
    pthread_mutex_unlock(&r->lock);
    
    if (rb->timer.expires >= 0)
        timer_del(&r->tq, &rb->timer);
    
    timer_queue_signal_raise(&r->tq);
}

static void check_for_cancelled_blocks(struct reactor *r, 
                                       struct list_head *cancel_list)
{
    struct reactor_block *rb, *tmp;
    /* Check for cancelled blocks */
    pthread_mutex_lock(&r->lock);
    
    list_for_each_entry_safe(rb, tmp, &r->block_list, block_node) {
        if (rb->cancel) {
            list_del(&rb->block_node);
            INIT_LIST_HEAD(&rb->block_node);
            list_add(&rb->callback_node, cancel_list);
            r->num_blocks--;
            rb->cancel = 0;
            LOG_DBG("Cancelling reactor block for fd=%d\n", rb->fd);
        }
    }
    pthread_mutex_unlock(&r->lock);
}

void reactor_loop(void *data)
{
    struct reactor *r = (struct reactor *)data;
    int ret = 0;

    LOG_DBG("Reactor running\n");

    while (!r->should_exit) {
        struct timespec timeout, *t = NULL;
        struct list_head priv_list;
        struct reactor_block *rb, *tmp;

        INIT_LIST_HEAD(&priv_list);

        ret = timer_next_timeout_timespec(&r->tq, &timeout);

        if (ret == 1)
            t = &timeout;
        
        LOG_DBG("Reactor waiting\n");

        ret = r->ops->wait(r, t);

        if (ret == REACTOR_TIMEOUT) {
            /* Timeout */
            LOG_DBG("Timeout!\n");
            ret = timer_handle_timeout(&r->tq);
            check_for_cancelled_blocks(r, &priv_list);
        } else if (ret == REACTOR_ERROR) {
            /* Error */
            LOG_DBG("wait error  %s\n", strerror(errno));
        } else if (ret == REACTOR_BLOCK_EVENT) {
            pthread_mutex_lock(&r->lock);
            
            list_for_each_entry_safe(rb, tmp, &r->block_list, block_node) {
                if (rb->revents || rb->cancel) {
                    list_del(&rb->block_node);
                    LOG_DBG("reactor block fd=%d removed\n", rb->fd);
                    INIT_LIST_HEAD(&rb->block_node);
                    list_add(&rb->callback_node, &priv_list);
                    r->num_blocks--;
                }
            }
            pthread_mutex_unlock(&r->lock);
        } else if (ret == REACTOR_TIMER_QUEUE) {
            ret = timer_queue_signal_lower(&r->tq);
            
            if (ret == TIMER_SIGNAL_EXIT) {
                struct reactor_block *rb;

                INIT_LIST_HEAD(&priv_list);

                LOG_DBG("Timer exit signal\n");

                pthread_mutex_lock(&r->lock);
                
                list_for_each_entry_safe(rb, tmp, &r->block_list, block_node) {
                    /* Cancel all reactor_blocks */
                    rb->cancel = 1;
                    list_del(&rb->block_node);
                    INIT_LIST_HEAD(&rb->block_node);
                    list_add(&rb->callback_node, &priv_list);
                    r->num_blocks--;
                    LOG_DBG("Setting cancel for reactor block for fd=%d\n", rb->fd);
                }

                pthread_mutex_unlock(&r->lock);
                break;
            } else if (ret == TIMER_SIGNAL_SET) {
                /* Reschedule timers */
                //LOG_DBG("Rescheduling wait\n");
                check_for_cancelled_blocks(r, &priv_list);
            }
        }

        /* Execute callbacks */
        while (!list_empty(&priv_list)) {
            rb = list_first_entry(&priv_list, struct reactor_block, callback_node);
            list_del(&rb->callback_node);
            INIT_LIST_HEAD(&rb->callback_node);
            LOG_DBG("Executing callback for fd=%d\n", rb->fd);
            if (rb->callback)
                rb->callback(rb->data);
        }
    }
    LOG_DBG("Reactor thread end of loop\n");
}

static int timer_callback(struct timer *t)
{
    struct reactor_block *rb = (struct reactor_block *)t;
    
    if (rb->callback)
        rb->callback(rb->data);

    return 0;
}

int reactor_block_init(struct reactor_block *rb,
                       int fd, unsigned short flags,
                       void (*callback)(void *data),
                       void *data,
                       long ms_timeout)
{
    memset(rb, 0, sizeof(*rb));
    timer_init(&rb->timer);
    rb->timer.callback = timer_callback;
    timer_set_msecs(&rb->timer, ms_timeout);
    INIT_LIST_HEAD(&rb->block_node);
    INIT_LIST_HEAD(&rb->callback_node);
    rb->data = data;
    rb->callback = callback;
    rb->fd = fd;
    rb->events = flags;

    LOG_DBG("Initialized reactor block for fd=%d\n", fd);

    return 0;
}

void reactor_stop(struct reactor *r)
{
    r->should_exit = 1;
    timer_queue_signal_raise(&r->tq);
}

void reactor_free(struct reactor *r)
{
    reactor_fini(r);
    free(r);
}

int reactor_init(struct reactor *r)
{
    pthread_mutexattr_t attr;

    INIT_LIST_HEAD(&r->block_list);

	if (timer_queue_init(&r->tq))
		return -1;
    
    r->should_exit = 0;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&r->lock, &attr);
    pthread_mutexattr_destroy(&attr);

	if (r->ops->init(r)) {
        timer_queue_fini(&r->tq);
        pthread_mutex_destroy(&r->lock);
        return -1;
    }
    return 0;
}

void reactor_fini(struct reactor *r)
{
    r->ops->fini(r);
	timer_queue_fini(&r->tq);
	pthread_mutex_destroy(&r->lock);
}

struct reactor *reactor_alloc(unsigned int size, struct reactor_ops *ops)
{
    struct reactor *r;

    r = malloc(size);

    if (!r)
        return NULL;

    memset(r, 0, size);

    r->ops = ops;

    if (reactor_init(r)) {
        free(r);
        return NULL;
    }

    return r;
}
