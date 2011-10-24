/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <libservalctrl/reactor.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>
#include "reactor_internal.h"

struct reactor_kqueue {
	struct reactor r;
	int fd;
};

static int reactor_kqueue_init(struct reactor *r)
{
    struct reactor_kqueue *rk = (struct reactor_kqueue *)r;

    rk->fd = kqueue();
    
    if (!rk->fd)
        return -1;

    return 0;
}

static void reactor_kqueue_fini(struct reactor *r)
{
    struct reactor_kqueue *rk = (struct reactor_kqueue *)r;

    if (rk->fd != -1) {
        close(rk->fd);
        rk->fd = -1;
    }
}

static int reactor_kqueue_wait(struct reactor *r, const struct timespec *t)
{
    struct reactor_kqueue *rk = (struct reactor_kqueue *)r;
    struct reactor_block *rb;
    struct kevent *kev;
    unsigned int num_kev, i = 0;
    int ret;

    num_kev = r->num_blocks + 1;
    
    kev = malloc(sizeof(struct kevent) * num_kev);
    
    if (!kev)       
        return -1;

    EV_SET(&kev[i++], timer_queue_get_signal(&r->tq), 
           EVFILT_READ, EV_ADD, 0, 0, NULL);

    pthread_mutex_lock(&r->lock);
     
    list_for_each_entry(rb, &r->block_list, lh) {
        if (rb->fd > 0 && rb->events != 0) {
            int flags = 0;
            
            if (rb->events & RF_READ)
                flags |= EVFILT_READ;
            
            if (rb->events & RF_WRITE)
                flags |= EVFILT_WRITE;
            
            EV_SET(&kev[i++], rb->fd, flags, EV_ADD, 0, 0, rb);
            
            rb->revents = 0;
        }
    }
    
    pthread_mutex_unlock(&r->lock);

    ret = kevent(rk->fd, kev, i, kev, num_kev, t);

    if (ret > 0) {
        num_kev = ret;
        ret = REACTOR_BLOCK_EVENT;
        i = 0;
       
        if (kev[i++].filter & EVFILT_READ)
            ret = REACTOR_TIMER_QUEUE;
        
        for (; i < num_kev; i++) {
            rb = (struct reactor_block *)kev[i].udata;
            
            if (kev[i].flags == EV_ERROR) {
                rb->events |= RF_ERROR;
            } else  {
                if (kev[i].filter & EVFILT_READ) 
                    rb->revents |= RF_READ;
                
                if (kev[i].filter & EVFILT_WRITE) 
                    rb->revents |= RF_WRITE;
            }
        }
    }

    free(kev);

    return ret;
}

struct reactor_ops kqueue_ops = {
    .init = reactor_kqueue_init,
    .fini = reactor_kqueue_fini,
    .wait = reactor_kqueue_wait,
};

struct reactor *reactor_create(void)
{
    return reactor_alloc(sizeof(struct reactor_kqueue), &kqueue_ops);
}
