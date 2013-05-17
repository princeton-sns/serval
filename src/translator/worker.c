/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- 
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <common/debug.h>
#include <sys/epoll.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/netfilter_ipv4.h>
#include "translator.h"
#include "client.h"
#include "worker.h"
#if defined(OS_ANDROID)
#include "splice.h"
#define EPOLLONESHOT (1u << 30)
#endif

#define MAX_EVENTS 100
#define ENABLE_SPLICE_DEBUG 1

static int socket_is_writable(struct socket *s, int *bytes)
{
        int bytes_queued = 0;
        int ret;

        ret = ioctl(s->fd, TIOCOUTQ, &bytes_queued);
        
        if (ret == -1) {
                LOG_ERR("ioctl error - %s\n", strerror(errno));
                return 0;
        }
        if (bytes)
                *bytes = bytes_queued;

        return s->sndbuf - bytes_queued;
}

#define writable_bytes(s,b) socket_is_writable(s,b)

/*
  Move data from one socket to another via a pipe. 

  For this to work, the 'from' socket must be readable, and the 'to'
  socket must be writable. Also, we want to make sure that we can
  always write as much as we read, because we do not want to leave
  data in the pipe connecting the sockets. To ensure that we do not
  read too much, we first check the available send buffer space on the
  'to' socket and only read this amount.

  If there isn't any buffer space in the 'to' socket, we must wait for
  writability on that socket. In the meantime, we must also stop
  monitoring readability on the 'from' socket, otherwise we will just
  continue to try and translate.
 */
static enum work_status work_translate(struct socket *from, 
                                       struct socket *to,
                                       int splicefd[2])
{
        ssize_t ret = 0, bytes_read = 0;
        size_t readlen, nbytes = 0;
        enum work_status status = WORK_OK;
        int bytes_queued = 0;
        
        readlen = writable_bytes(to, &bytes_queued);
        
        LOG_MIN("%d -> %d translating up to %zu\n", 
                from->fd, to->fd, readlen);
        
        if (readlen == 0) {
                /* There wasn't enough space in send buffer of the
                 * socket we are writing to, we need to stop monitor
                 * readability on the "from" socket and instead watch
                 * for writability on the "to" socket. */
                from->monitored_events &= ~EPOLLIN;
                to->monitored_events |= EPOLLOUT;
                LOG_MED("fd=%d bufspace is 0, bytes_queued=%d sndbuf_size=%u\n",
                        to->fd, bytes_queued, to->sndbuf);
                return WORK_NOSPACE;
        }
        
        /* Make sure we write to the pipe atomically without
         * blocking */
        if (readlen > PIPE_BUF)
                readlen = PIPE_BUF;
        
        while (bytes_read < readlen && status == WORK_OK) {
                ret = splice(from->fd, NULL, splicefd[1], NULL, 
                                     readlen, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                
                if (ret == -1) {
                        if (errno == EWOULDBLOCK) {
                                /* Stop splicing to pipe if we block */
                                LOG_MED("splice1 would block\n");
                                break;
                        } else { 
                                LOG_ERR("client %u splice1 from %s %s\n",
                                        from->c->id, 
                                        &from->c->sock[ST_INET] == from ? 
                                        "INET" : "SERVAL",
                                        strerror(errno));

                                if (bytes_read > 0)
                                        break;
                                status = WORK_ERROR;
                        }
                        goto out;
                } else if (ret == 0) {
                        LOG_DBG("client %u splice1: %s end closed\n", 
                                from->c->id, 
                                &from->c->sock[ST_INET] == from ? 
                                "INET" : "SERVAL");

                         if (bytes_read > 0)
                                break;
                        status = WORK_CLOSE;

                        goto out;
                } else if (ret > 0) {
                        bytes_read += ret;
                        readlen -= ret;
                }
        }
        
        readlen = bytes_read;
        from->bytes_read += bytes_read;
        
        LOG_MED("splice1 %zu bytes\n", readlen);
       
        while (readlen && status == WORK_OK) {
                ret = splice(splicefd[0], NULL, to->fd, NULL,
                             readlen, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                
                if (ret == -1) {
                        if (errno == EPIPE) {
                                LOG_DBG("client %u splice2: EPIPE\n", from->c->id);
                                status = WORK_ERROR;
                        } else if (errno == EWOULDBLOCK) {
                                /* Try again */
                        } else {
                                LOG_ERR("client %u splice2: to %s %s\n",
                                        from->c->id,
                                        &to->c->sock[ST_INET] == to ? "INET" : "SERVAL",
                                        strerror(errno));
                                status = WORK_ERROR;
                        }
                } else if (ret > 0) {
                        to->bytes_written += ret;
                        nbytes += ret;
                        readlen -= ret;
                }
        }
        
#if defined(ENABLE_DEBUG)
        if (readlen) {
                LOG_ERR("client %u read/write mismatch (%zu bytes)\n",
                        from->c->id, readlen);
        }
#endif
        
 out:

        LOG_MED("splice2 %zu bytes\n", nbytes);

        to->monitored_events &= ~EPOLLOUT;
        from->monitored_events |= EPOLLIN;
        return status;
}

static enum work_status work_inet_to_serval(struct client *c)
{
        /* LOG_DBG("INET to SERVAL\n"); */
        return work_translate(&c->sock[ST_INET], 
                              &c->sock[ST_SERVAL], c->splicefd);
}

static enum work_status work_serval_to_inet(struct client *c)
{
        /* LOG_DBG("SERVAL to INET\n"); */
        return work_translate(&c->sock[ST_SERVAL], 
                              &c->sock[ST_INET], c->splicefd);
}

static enum work_status work_close(struct client *c)
{
        client_close(c);
        return WORK_OK;
}

static void check_socket_events(struct client *c, struct socket *s, 
                                unsigned int events)
{
        struct socket *s2;
        
        if (s->state == SS_CLOSED)
                return;

        if (s == &c->sock[ST_INET]) {
                s2 = &c->sock[ST_SERVAL];
        } else {
                s2 = &c->sock[ST_INET];
        }

        LOG_MAX("s(fd=%d) state=%s events[R=%d W=%d H=%u] "
                "active[R=%d W=%d H=%u] monitored[R=%d W=%d H=%u] "
                "s2(fd=%d) active[R=%d W=%d H=%u] monitored[R=%d W=%d H=%u]\n",
                s->fd, 
                socket_state_str[s->state],
                (events & EPOLLIN) > 0,
                (events & EPOLLOUT) > 0,
                (events & EPOLLRDHUP) > 0,
                (s->active_events & EPOLLIN) > 0, 
                (s->active_events & EPOLLOUT) > 0,
                (s->active_events & EPOLLRDHUP) > 0,
                (s->monitored_events & EPOLLIN) > 0, 
                (s->monitored_events & EPOLLOUT) > 0,
                (s->monitored_events & EPOLLRDHUP) > 0,
                s2->fd, 
                (s2->active_events & EPOLLIN) > 0, 
                (s2->active_events & EPOLLOUT) > 0,
                (s2->active_events & EPOLLRDHUP) > 0,
                (s2->monitored_events & EPOLLIN) > 0, 
                (s2->monitored_events & EPOLLOUT) > 0,
                (s2->monitored_events & EPOLLRDHUP) > 0);

        if (events & EPOLLRDHUP) {
                /* Other end of this socket's connection closed */
                s->active_events &= ~EPOLLRDHUP;
                client_add_work(c, work_close);          
        }
        
        /* 
           There is something to read on a socket. We must make sure
           that the other socket is also writable for splicing to
           work. If, not, stop monitoring reads, and wait for a write
           event. 
        */
        if (events & EPOLLIN) { if (s2->active_events & EPOLLOUT) {
                        /* We can translate stuff from s to s2 */
                        s->active_events &= ~EPOLLIN;
                       
                        if (s == &c->sock[ST_INET])
                                client_add_work(c, work_inet_to_serval);
                        else
                                client_add_work(c, work_serval_to_inet);
                } else {
                        s2->monitored_events |= EPOLLOUT;
                }
                s->monitored_events &= ~EPOLLIN;
        } 

        /*
          A socket (s) is writable. If the other socket (s2) was
          previously readable, then we are ready to execute a splice
          between the sockets. Otherwise, wait for read event on s2. */
        if (events & EPOLLOUT) {
                /* Socket was in async connect(). EPOLLOUT means the
                 * connect-call has completed. We must check the
                 * results. */
                if (s->state == SS_CONNECTING) {
                        s->monitored_events &= ~EPOLLOUT;
                        s->active_events &= ~EPOLLOUT;
                        client_add_work(c, client_connect_result);
                        return;
                }
                if (s2->active_events & EPOLLIN) {
                        /* We can translate stuff from s2 to s */
                        s->active_events &= ~EPOLLOUT;
                        
                        if (s2 == &c->sock[ST_INET]) 
                                client_add_work(c, work_inet_to_serval);
                        else
                                client_add_work(c, work_serval_to_inet);
                } else {
                        s2->monitored_events |= EPOLLIN;
                }
                s->monitored_events &= ~EPOLLOUT;
        }
}

static void worker_cleanup_clients(struct worker *w)
{
        /* 
           We do not need lock protection on the new_clients list here
           (which is normally shared with main thread), since this
           function wouldn't be called unless the main thread has
           stopped running and wants all workers to exit */
        while (!list_empty(&w->new_clients) || 
               !list_empty(&w->active_clients)) {
                struct client *c;

                if (!list_empty(&w->new_clients))
                        c = list_first_entry(&w->new_clients, 
                                             struct client, lh);
                else
                        c = list_first_entry(&w->active_clients, 
                                             struct client, lh);
		
                LOG_DBG("cleaning up client %u\n", c->id);
                client_close(c);
                /* client_free removes client from list */
                client_free(c);
        }
}

/*
  After a worker has been notified by the main thread that it has been
  assigned a new client, the worker moves the client to its active
  client list, and starts to monitor events on the client's sockets.
 */
static void worker_accept_clients(struct worker *w)
{
        pthread_mutex_lock(&w->lock);
        
        while (!list_empty(&w->new_clients)) {
                struct client *c = list_first_entry(&w->new_clients, 
                                                    struct client, lh);
                LOG_DBG("w=%u accepts client %u\n", w->id, c->id);
                list_move_tail(&c->lh, &w->active_clients);
                c->w = w;
                client_epoll_set(c, &c->sock[ST_SERVAL], EPOLL_CTL_ADD, 
                                 EPOLLONESHOT);
                client_epoll_set(c, &c->sock[ST_INET], EPOLL_CTL_ADD, 
                                 EPOLLONESHOT);
        }
        
        pthread_mutex_unlock(&w->lock);
}

/*
  A worker's main loop. The worker waits and acts on three types of
  events: 

  1) exit signal
  2) new client assigned
  3) socket event on active client

  1,2 are straightforward. On 3), the worker will check for which
  socket events are active, and then determine which type of work to
  execute (e.g., close, or translate INET-to-SERVAL or
  SERVAL-to-INET).  
*/  
static void *worker_thread(void *arg)
{
        struct worker *w = (struct worker *)arg;
        struct epoll_event events[MAX_EVENTS];
        int sig_fd = signal_get_fd(&w->sig);

        w->running = 1;

        LOG_DBG("Worker %u running\n", w->id);

        while (w->running) {
                unsigned int i;
                int nfds;

                nfds = epoll_wait(w->epollfd, events, MAX_EVENTS, -1);
                
                if (nfds == -1) {
                        if (errno == EINTR) {
                                /* Just exit */
                        } else {
                                LOG_ERR("epoll_wait: %s\n",
                                        strerror(errno));
                        }
                        break;
                } 
                
                for (i = 0; i < nfds; i++) {
                        /* We can cast to struct socket here since we
                           know fd is first member of the struct */
                        struct socket *s = (struct socket *)events[i].data.ptr;

                        if (s->fd == sig_fd) {
                                /* Signal raised */
                                int val;
                                
                                signal_clear_val(&w->sig, &val);
                                
                                switch (val) {
                                case SIGNAL_EXIT:
                                        LOG_DBG("worker exit signal\n");
                                        w->running = 0;
                                        break;
                                case SIGNAL_NEW_CLIENT:
                                        worker_accept_clients(w);
                                default:
                                        break;
                                }
                        } else {
                                struct client *c = s->c;
                                unsigned int j, exit = 0;
                                
                                s->active_events |= events[i].events;
                                check_socket_events(c, s, events[i].events);
                                
                                for (j = 0; j < c->num_work && !exit; j++) {
                                        enum work_status status;
                                        
                                        status = c->work[j](c);
                                        
                                        switch (status) {
                                        case WORK_ERROR:
                                                LOG_ERR("work error, closing socket\n");
                                        case WORK_CLOSE:
                                                client_close(c);
                                                exit = 1;
                                                break;
                                        case WORK_NOSPACE:
                                        case WORK_OK:
                                        default:
                                                break;
                                        }
                                }
                                c->num_work = 0;
                                
                                if (exit) {
                                        /* The client is done */
                                        client_free(c);
                                } else {
                                        /* Reactivate socket monitoring */
                                        client_epoll_set_all(c, EPOLL_CTL_MOD,
                                                             EPOLLONESHOT);
                                }
                        }
                }     
        }
        
        w->running = 0;
        worker_cleanup_clients(w);
        LOG_DBG("Worker %u exits\n", w->id);

        return NULL;
}

int worker_start(struct worker *w)
{
        int ret;

        ret = pthread_create(&w->thr, NULL, worker_thread, w);
        
        if (ret != 0) {
                LOG_ERR("pthread_create: %s\n",
                        strerror(errno));
        }
        return ret;
}

int worker_init(struct worker *w, unsigned id)
{
        struct epoll_event ev;
        int ret;

        memset(w, 0, sizeof(struct worker));
        INIT_LIST_HEAD(&w->new_clients);
        INIT_LIST_HEAD(&w->active_clients);
        w->id = id;
        w->epollfd = epoll_create(10);
        
        if (w->epollfd == -1) {
                LOG_ERR("epoll: %s\n", strerror(errno));
                return -1;
        }

        ret = signal_init(&w->sig);
        
        if (ret == -1) {
                LOG_ERR("signal_init: %s\n", strerror(errno));
                close(w->epollfd);
                return -1;
        }
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN;
        ev.data.ptr = &w->sig.fd[0];
        
        ret = epoll_ctl(w->epollfd, EPOLL_CTL_ADD, 
                        signal_get_fd(&w->sig), &ev);
        
        if (ret == -1) {
                LOG_ERR("epoll_ctl: %s\n", strerror(errno));
                close(w->epollfd);
                signal_destroy(&w->sig);
                return -1;
        }

        pthread_mutex_init(&w->lock, NULL);
        
        return 0;
}
 
void worker_destroy(struct worker *w)
{
        signal_destroy(&w->sig);
        close(w->epollfd);
        pthread_mutex_destroy(&w->lock);
}

int worker_add_client(struct worker *w, struct client *c)
{
        pthread_mutex_lock(&w->lock);
        list_add(&c->lh, &w->new_clients);
        pthread_mutex_unlock(&w->lock);
        w->num_clients++;
        signal_raise_val(&w->sig, SIGNAL_NEW_CLIENT);
        return 0;
}
