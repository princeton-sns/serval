/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <common/debug.h>
#include <libservalctrl/reactor.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "reactor_internal.h"

struct reactor_epoll {
	struct reactor r;
	int fd;
};

static int reactor_epoll_init(struct reactor *r)
{
    struct reactor_epoll *rk = (struct reactor_epoll *)r;

    /* Create epoll queue, the size argument is ignored nowadays, but
     * just give some value to be sure. */
    rk->fd = epoll_create(100); 
    
    if (!rk->fd)
        return -1;

    return 0;
}

static void reactor_epoll_fini(struct reactor *r)
{
    struct reactor_epoll *rk = (struct reactor_epoll *)r;

    if (rk->fd != -1) {
        close(rk->fd);
        rk->fd = -1;
    }
}

static int reactor_epoll_wait(struct reactor *r, const struct timespec *t)
{
    struct reactor_epoll *rk = (struct reactor_epoll *)r;
    struct reactor_block *rb;
    struct epoll_event *ee, ev;
    unsigned int num_ee = 0;
    int ret, timeout;

    memset(&ev, 0, sizeof(ev));
    ev.data.ptr = NULL;
    ev.events = EPOLLIN;
    num_ee++;

    epoll_ctl(rk->fd, EPOLL_CTL_ADD, timer_queue_get_signal(&r->tq), &ev);

    pthread_mutex_lock(&r->lock);

    list_for_each_entry(rb, &r->block_list, block_node) {
        if (rb->fd > 0 && rb->events != 0) {
            memset(&ev, 0, sizeof(ev));

            //LOG_DBG("epolling fd=%d\n", rb->fd);
            
            if (rb->events & RF_READ)
                ev.events |= EPOLLIN;
            
            if (rb->events & RF_WRITE)
                ev.events |= EPOLLOUT;
            
            if (rb->events & RF_ERROR)
                ev.events |= EPOLLERR;
            
            ev.data.ptr = rb;
            
            epoll_ctl(rk->fd, EPOLL_CTL_ADD, rb->fd, &ev);
            
            rb->revents = 0;
            num_ee++;
        }
    }
    pthread_mutex_unlock(&r->lock);

    LOG_DBG("Waiting on %u blocks\n", num_ee - 1);

    ee = malloc(sizeof(struct epoll_event) * num_ee);

    if (!ee)
        return -1;

    memset(ee, 0, sizeof(struct epoll_event) * num_ee);

    if (!t)
        timeout = -1;
    else
        timeout = t->tv_sec * 1000 + t->tv_nsec / 1000000;

    //LOG_DBG("calling epoll_wait\n");

    while (1) {
        ret = epoll_wait(rk->fd, ee, num_ee, timeout);

        if (ret == -1) {        
            if (errno == EINTR)
                continue;
            //LOG_DBG("epoll_wait: %s\n", strerror(errno));
        }
        break;
    }

    //LOG_DBG("epoll_wait returned %d\n", ret);

    if (ret > 0) {
        unsigned int i;
        num_ee = ret;
        ret = REACTOR_BLOCK_EVENT;
        
        for (i = 0; i < num_ee; i++) {
            rb = (struct reactor_block *)ee[i].data.ptr;

            /* rb == NULL means timer interrupt */
            if (rb == NULL) {
                //LOG_DBG("Timer interrupt\n");
                ret = REACTOR_TIMER_QUEUE;
            } else {
                if (ee[i].events & EPOLLIN)
                    rb->revents |= RF_READ;

                if (ee[i].events & EPOLLOUT)
                    rb->revents |= RF_WRITE;
                
                if (ee[i].events & EPOLLERR)
                    rb->revents |= RF_ERROR;

                //LOG_DBG("fd=%d events=%x\n", rb->fd, rb->events);
                epoll_ctl(rk->fd, EPOLL_CTL_DEL, rb->fd, &ev);
            }
        }
    } 

    free(ee);

    return ret;
}

struct reactor_ops epoll_ops = {
    .init = reactor_epoll_init,
    .fini = reactor_epoll_fini,
    .wait = reactor_epoll_wait,
};

struct reactor *reactor_create(void)
{
    return reactor_alloc(sizeof(struct reactor_epoll), &epoll_ops);
}
