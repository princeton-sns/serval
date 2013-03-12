/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- 
 *
 * A translator between traditional TCP sockets and Serval TCP sockets.
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
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <netinet/serval.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <common/signal.h>
#include <common/list.h>
#include <common/timer.h>
#define ENABLE_DEBUG 1
#include <common/debug.h>
#include <sys/epoll.h>
#include <poll.h>
#include <pthread.h>
#include <linux/netfilter_ipv4.h>
#include "log.h"

#if defined(OS_ANDROID)
#include "splice.h"
#endif

/* 
   High-level overview of translator
   =================================

   The translator moves data between two sockets (AF_INET and
   AF_SERVAL) using the splice system call. With this call, the data
   never leaves kernel space, and the whole operation is therefore
   very efficient. The translator can accept connections on both types
   of sockets simultaneously and then automatically create a socket of
   the other type, connecting to the final server destination.

   The splice call requires connecting the two sockets via pipes,
   leaving us with a configuration as follows (when translating from
   AF_INET to AF_SERVAL):

   fd_inet ---> fd_pipe_w PIPE fd_pipe_r ---> fd_serval

   All in all, this leaves us with four file descriptors per client
   that connects to the translator.

   There are tricky blocking situations to consider between these file
   descriptors: for instance, there may be incoming data on the SERVAL
   socket, which we want to write to the INET socket, but the receive
   buffer on the INET socket may be full. So, although a
   poll/epoll/select, may indicate non-blocking readability, we could
   still block because the target socket is not writable. Also,
   leaving data in the pipe might be dangerous since we are using the
   same pipe to translate in both directions (we could use one pipe
   for each direction, but that would require even more
   filedescriptors, and additional monitoring of
   those). Unfortunately, there is no easy way to monitor for complex
   conditions that span multiple file descriptors.

   With the above complexities in mind, the strategy used for
   non-blocking operation is as follows. We only read as much data as
   we can write to the target socket, ensuring that we never fill the
   pipe with data that we cannot read out of the pipe. We use a
   TIOCOUTQ ioctl() call on the target socket to learn how much free
   space there is in the receive buffer and cap the amount of bytes
   read from the source socket at this value. This ensures we never
   read more than we can write to the target socket and we will never
   leave data in the pipe.

   We monitor he INET and SERVAL file descriptors for read/write
   events, and we never translate anything unless we've seen a
   combination of readability on the source socket and writability on
   the target socket. Since we cannot monitor read/write events across
   file descriptors as a single event, we need a way to "remember" the
   last state of a file descriptor in order to wait for the
   corresponding event on the other file descriptor. Also, if a socket
   is readable, but the target is not writable, we need to stop
   monitoring readability on the source until the target is
   writable. Otherwise, we will spin in a busy "readability"-loop
   until we can write the data.

   
   Threading
   ---------

   The translator uses a fixed number of worker threads and epoll for
   scalability. The number of worker threads to use is a runtime
   configurable setting.

   The main thread monitors a client's file descriptors for
   events. When the right conditions occur for translating data, the
   main thread schedules the client on a work queue for processing,
   and stops monitoring its file descriptors. A worker thread will
   pick the client off the work queue and perform the
   translation. When translation has finished, the worker signals the
   main thread to "rearm" all non-scheduled clients so that the client
   that just finished will have its file descriptors monitored again.
 */

static unsigned int client_num = 0;

typedef union sockaddr_generic {
        struct sockaddr sa;
        struct sockaddr_sv sv;
        struct sockaddr_in in;
        struct {
                struct sockaddr_sv sv;
                struct sockaddr_in in;
        } sv_in;
} sockaddr_generic_t;

struct worker {
        unsigned int id;
        pthread_t thr;
        int running;
};

struct client;

enum socket_state {
        SS_CLOSED,
        SS_CONNECTING,
        SS_CONNECTED,
        SS_CLOSING,
};

const char *socket_state_str[] = {
        "CLOSED",
        "CONNECTING",
        "CONNECTED",
        "CLOSING"
};

struct socket {
        int fd; /* Must be first */
        enum socket_state state;
        struct client *c;
        char is_monitored:1;
        uint32_t monitored_events;
        uint32_t active_events;
        sockaddr_generic_t addr;
        socklen_t addrlen;
        size_t bytes_written, bytes_read;
        socklen_t sndbuf;
};

enum sockettype {
        ST_INET,
        ST_SERVAL,
};

enum work_status {
        WORK_OK,
        WORK_CLOSE,
        WORK_NOSPACE,
        WORK_ERROR,
};

#define MAX_WORK 4

typedef enum work_status (*work_t)(struct client *c);

struct client {
        int from_family;
        unsigned int id;
        struct socket sock[2];
        int translator_port;
        int splicefd[2];
        unsigned int num_work;
        work_t work[MAX_WORK];
        unsigned char is_scheduled:1;
        unsigned char is_garbage:1;
        unsigned char cross_translate:1;
        struct list_head lh, wq;
};

struct translator_init_pkt {
        struct in_addr addr;
        uint16_t port;
} __attribute__((packed));

#define DEFAULT_TRANSLATOR_PORT 8080
#define DEFAULT_SERVICE_ID "0x0000005"
static LOG_DEFINE(logh);
static LIST_HEAD(client_list);
static int epollfd = -1;
struct signal main_signal;

enum signal_types {
        SIGNAL_EXIT = 1,
        SIGNAL_EPOLL_REARM,
};

static int client_add_work(struct client *c, work_t work);
static enum work_status client_close(struct client *c);

static const char *family_to_str(int family)
{
        static const char *family_inet = "AF_INET";
        static const char *family_serval = "AF_SERVAL";
        static const char *unknown = "UNKNOWN";
        
        switch (family) {
        case AF_INET:
                return family_inet;
        case AF_SERVAL:
                return family_serval;
        default:
                break;
        }
        return unknown;
}

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

static enum work_status work_translate(struct socket *from, 
                                       struct socket *to,
                                       int splicefd[2])
{
        ssize_t ret;
        size_t readlen, nbytes = 0;
        enum work_status status = WORK_OK;
        int bytes_queued = 0;
        
        readlen = writable_bytes(to, &bytes_queued);
        
        LOG_DBG("translating up to %zu bytes from %d to %d\n", 
                readlen, from->fd, to->fd); 

        if (readlen == 0) {
                /* There wasn't enough space in send buffer of the
                 * socket we are writing to, we need to stop monitor
                 * readability on the "from" socket and instead watch
                 * for writability on the "to" socket. */
                from->monitored_events &= ~EPOLLIN;
                to->monitored_events |= EPOLLOUT;
                LOG_DBG("fd=%d bufspace is 0, bytes_queued=%d sndbuf_size=%u\n",
                        to->fd, bytes_queued, to->sndbuf);
                return WORK_NOSPACE;
        }
        
        /* Make sure we write to the pipe atomically without
         * blocking */
        if (readlen > PIPE_BUF)
                readlen = PIPE_BUF;
        
        ret = splice(from->fd, NULL, splicefd[1], NULL, 
                     readlen, SPLICE_F_MOVE);
        
        if (ret == -1) {
                if (errno == EWOULDBLOCK) {
                        /* Just return and retry */
                } else { 
                        status = WORK_ERROR;
                        LOG_ERR("client %u splice1 from %s %s\n",
                                from->c->id, 
                                &from->c->sock[ST_INET] == from ? "INET" : "SERVAL",
                                strerror(errno));
                }                
                goto out;
        } else if (ret == 0) {
                LOG_DBG("client %u splice1: %s end closed\n", 
                        from->c->id, 
                        &from->c->sock[ST_INET] == from ? "INET" : "SERVAL");
                status = WORK_CLOSE;
                goto out;
        }       
        
        readlen = ret;
        from->bytes_read += readlen;

        /* LOG_DBG("splice1 %zu bytes\n", readlen); */
         
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
        LOG_DBG("splice2 %zu bytes\n", nbytes); 
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

static int client_epoll_set(struct client *c, struct socket *s, 
                            int op, unsigned int extra_event)
{
        struct epoll_event ev;
        int ret;

        if (c->is_garbage)
                return -1;
        
        memset(&ev, 0, sizeof(ev));
        ev.events = s->monitored_events | extra_event;
        ev.data.ptr = s;
        
        switch (op) {
        case EPOLL_CTL_ADD:
                if (s->is_monitored)
                        return 0;
                s->is_monitored = 1;
                break;
        case EPOLL_CTL_DEL:
                if (!s->is_monitored)
                        return 0;
                s->is_monitored = 0;
                break;
        case EPOLL_CTL_MOD:
                if (!s->is_monitored)
                        return 0;
                break;
        default:
                return 0;
        }
/*        
        LOG_DBG("client=%u op=%s fd=%d R=%d W=%d H=%d\n",
                c->id,
                EPOLL_CTL_MOD == op ?                                
                "EPOLL_CTL_MOD" :
                (EPOLL_CTL_ADD == op ? "EPOLL_CTL_ADD" : "EPOLL_CTL_DEL"),
                s->fd,
                (ev.events & EPOLLIN) > 0, 
                (ev.events & EPOLLOUT) > 0,
                (ev.events & EPOLLHUP) > 0);
*/      
        ret = epoll_ctl(epollfd, op, s->fd, &ev);
        
        if (ret == -1) {
                LOG_ERR("epoll_ctl op=%d fd=%d: %s\n",
                        op, s->fd, strerror(errno));
        }
        
        return ret;
}

static int client_epoll_set_all(struct client *c, int op, 
                                unsigned int extra_event)
{               
        unsigned int i;
        int ret = 0;

        if (c->is_garbage)
                return -1;

        for (i = 0; i < 2; i++) {
                ret = client_epoll_set(c, &c->sock[i], op,
                                       extra_event);
                
                if (ret == -1)
                        break;
        }
        
        return ret;
}

struct client *client_create(int sock, struct sockaddr *sa, 
                             socklen_t salen, int cross_translate)
{
        struct client *c;
        int ret, i;

        c = malloc(sizeof(struct client));

        if (!c)
                return NULL;
        
        memset(c, 0, sizeof(struct client));
        c->id = client_num++;
        c->from_family = sa->sa_family;
        c->is_garbage = 0;
        c->cross_translate = cross_translate == 1;
        c->sock[0].c = c->sock[1].c = c;
        INIT_LIST_HEAD(&c->lh);
        INIT_LIST_HEAD(&c->wq);
        
        ret = pipe(c->splicefd);

        if (ret == -1) {
                LOG_ERR("pipe: %s\n",
			strerror(errno));
                goto fail_pipe;
        }
        
        if (c->from_family == AF_INET) {
                /* We're translating from AF_INET to AF_SERVAL */
                c->sock[ST_INET].fd = sock;
                memcpy(&c->sock[ST_INET].addr, sa, 
                       sizeof(struct sockaddr_in));
                c->sock[ST_INET].addrlen = sizeof(struct sockaddr_in);
                c->sock[ST_INET].state = SS_CONNECTED;
                c->sock[ST_INET].monitored_events = 0;
                c->sock[ST_INET].active_events = 0;
                c->sock[ST_SERVAL].state = SS_CLOSED;
                c->sock[ST_SERVAL].monitored_events = EPOLLOUT;
                c->sock[ST_SERVAL].active_events = 0;

                c->sock[ST_SERVAL].fd = socket(AF_SERVAL, SOCK_STREAM, 0);
                
                if (c->sock[ST_SERVAL].fd == -1) {
                        LOG_ERR("serval socket: %s\n",
                                strerror(errno));
                        goto fail_sock;
                }
                client_epoll_set(c, &c->sock[ST_SERVAL], EPOLL_CTL_ADD, 0);
        } else if (c->from_family == AF_SERVAL) {
                struct sockaddr_sv sv;
                socklen_t svlen = sizeof(sv);

                /* We're translating from AF_SERVAL to AF_INET */
                c->sock[ST_SERVAL].fd = sock;
                memcpy(&c->sock[ST_SERVAL].addr, sa, 
                       sizeof(struct sockaddr_sv));
                c->sock[ST_SERVAL].addrlen = sizeof(struct sockaddr_sv);
                c->sock[ST_SERVAL].state = SS_CONNECTED;
                c->sock[ST_SERVAL].monitored_events = 0;
                c->sock[ST_SERVAL].active_events = 0;
                c->sock[ST_INET].state = SS_CLOSED;
                c->sock[ST_INET].monitored_events = EPOLLOUT;
                c->sock[ST_INET].active_events = 0;

                c->sock[ST_INET].addr.in.sin_family = AF_INET;
                        
                if (c->cross_translate) {
                        ret = getsockname(c->sock[ST_SERVAL].fd, (struct sockaddr *)&sv, &svlen);
                        
                        if (ret == -1) {
                                LOG_DBG("getsockname: %s\n", strerror(errno));
                                goto fail_sock;
                        }
                        
                        /* The end of the serviceID contains the original port
                           and IP. */ 
                        c->sock[ST_INET].addr.in.sin_addr.s_addr = sv.sv_srvid.s_sid32[7];
                        c->sock[ST_INET].addr.in.sin_port = sv.sv_srvid.s_sid16[13];
                } else {
                        /* We need a way to map a serviceID to an IP address. */
                        LOG_ERR("serviceID lookup not implemented\n");
                        goto fail_sock;
                }
                
                c->sock[ST_INET].fd = socket(AF_INET, SOCK_STREAM, 0);
                
                if (c->sock[ST_INET].fd == -1) {
                        LOG_ERR("inet socket: %s\n",
                                strerror(errno));
                        goto fail_sock;
                }
                client_epoll_set(c, &c->sock[ST_INET], EPOLL_CTL_ADD, 0);
        } else {
                LOG_ERR("Unsupported client family\n");
                goto fail_sock;
        }
        
        for (i = 0; i < 2; i++) {
                socklen_t len = sizeof(c->sock[i].sndbuf);
                long flags;

                ret = getsockopt(c->sock[i].fd, SOL_SOCKET, 
                                 SO_SNDBUF, &c->sock[i].sndbuf, 
                                 &len);
                
                if (ret == -1) {
                        LOG_ERR("getsockopt(sndbuf) - %s\n", strerror(errno));
                }

                flags = fcntl(c->sock[i].fd, F_GETFL, ret);

                if (flags == -1) {
                        LOG_ERR("fctnl(F_GETFL): %s\n", strerror(errno));
                        goto fail_post_sock;
                }
                
                ret = fcntl(c->sock[i].fd, F_SETFL, flags | O_NONBLOCK);

                if (ret == -1) {
                        LOG_ERR("fctnl(F_SETFL): %s\n", strerror(errno));
                        goto fail_post_sock;
                }
        }

        return c;

fail_post_sock:
        if (c->sock[1].fd == sock)
                close(c->sock[0].fd);
        else
                close(c->sock[1].fd);
 fail_sock:
        close(c->splicefd[0]);
        close(c->splicefd[1]);
 fail_pipe:
        close(sock);
        free(c);
        return NULL;
}

static void client_free(struct client *c)
{
        free(c);
}

static int client_add_work(struct client *c, work_t work)
{
        if (c->num_work == MAX_WORK)
                return -1;
        
        c->work[c->num_work++] = work;
        return 0;
}

static pthread_cond_t work_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t work_mutex = PTHREAD_MUTEX_INITIALIZER;
static int worker_running = 1;
static LIST_HEAD(workq);

static void *worker_thread(void *arg)
{
        struct worker *w = (struct worker *)arg;
        int ret = 0;
        struct client *c;
        
        w->running = 1;

        LOG_DBG("Worker %u running\n", w->id);

        while (worker_running) {
                unsigned int i;

                pthread_mutex_lock(&work_mutex);
                
                if (list_empty(&workq)) {
                        ret = pthread_cond_wait(&work_cond, 
                                                &work_mutex);
                
                        if (ret != 0) {
                                LOG_ERR("condition error\n");
                                worker_running = 0;
                                break;
                        }
                }
                
                if (list_empty(&workq)) {
                        pthread_mutex_unlock(&work_mutex);
                        continue;
                }              

                c = list_first_entry(&workq, struct client, wq);

                list_del_init(&c->wq);
                pthread_mutex_unlock(&work_mutex);

                for (i = 0; i < c->num_work && !c->is_garbage; i++) {
                        enum work_status status;
                        
                        status = c->work[i](c);
                        
                        switch (status) {
                        case WORK_ERROR:
                                LOG_ERR("work error, closing socket\n");
                        case WORK_CLOSE:
                                client_close(c);
                                break;
                        case WORK_NOSPACE:
                        case WORK_OK:
                        default:
                                break;
                        }
                }

                c->is_scheduled = 0;
                c->num_work = 0;

                if (!c->is_garbage)
                        signal_raise_val(&main_signal, SIGNAL_EPOLL_REARM);
        }
        
        LOG_DBG("Worker %u exits\n", w->id);

        return NULL;
}

static enum work_status client_connect(struct client *c)
{
        sockaddr_generic_t addr;
        socklen_t addrlen;
        struct socket *s, *s2;
        char ipstr[18];
        int ret;

        memset(&addr, 0, sizeof(addr));
        
        if (c->from_family == AF_SERVAL) {
                addrlen = sizeof(addr.in);
                memcpy(&addr, &c->sock[ST_INET].addr, addrlen);
                s = &c->sock[ST_INET];
                s2 = &c->sock[ST_SERVAL];

                inet_ntop(AF_INET, &addr.in.sin_addr, 
                          ipstr, sizeof(ipstr));
                
                LOG_DBG("client %u connecting to %s:%u on fd=%d\n",
                        c->id, ipstr, ntohs(addr.in.sin_port), s->fd);
        } else if (c->from_family == AF_INET) {
                addr.sv.sv_family = AF_SERVAL;
                addr.sv.sv_srvid.s_sid32[0] = htonl(c->translator_port);

                if (c->cross_translate) {
                        struct sockaddr_in orig_addr;
                        socklen_t orig_addrlen = sizeof(orig_addr);

                        /* We are cross translating, i.e., this
                         * AF_INET to AF_SERVAL translator connects to
                         * another AF_SERVAL to AF_INET translator. We
                         * put the original AF_INET destination
                         * address and port at the end of the
                         * serviceID, so that the other translator
                         * knows where to connect to. NOTE: The other
                         * translator must listen to a serviceID
                         * prefix, since every serviceID will now be
                         * unique. */
                        
                        ret = getsockopt(c->sock[ST_INET].fd, SOL_IP, 
                                         SO_ORIGINAL_DST, 
                                         &orig_addr, &orig_addrlen);
                        
                        if (ret == -1) {
                                LOG_ERR("client %u: could not get original port: %s\n", c->id, strerror(errno));
                                return WORK_ERROR;
                        } else {
                                inet_ntop(AF_INET, &orig_addr.sin_addr, 
                                          ipstr, sizeof(ipstr));
                                
                                LOG_DBG("Original destination: %s:%u\n",
                                        ipstr, ntohs(orig_addr.sin_port));
                        }

                        addr.sv.sv_srvid.s_sid16[13] = orig_addr.sin_port;
                        addr.sv.sv_srvid.s_sid32[7] = orig_addr.sin_addr.s_addr;
                }

                addrlen = sizeof(addr.sv);
                s = &c->sock[ST_SERVAL];
                s2 = &c->sock[ST_INET];

                inet_ntop(AF_INET, &c->sock[ST_INET].addr.in.sin_addr, 
                          ipstr, 18);

                LOG_DBG("client %u from %s connecting to service %s on fd=%d...\n",
                        c->id, ipstr, service_id_to_str(&addr.sv.sv_srvid), s->fd);
        } else {
                LOG_ERR("client %u - bad address family, exiting\n",
                        c->id);
                return WORK_ERROR;
        }

        s->state = SS_CONNECTING;
       
        ret = connect(s->fd, &addr.sa, addrlen);

        if (ret == -1) {
                if (errno == EINPROGRESS) {
                        s->monitored_events = EPOLLOUT;
                } else {
                        LOG_ERR("client %u connect failed: %s\n",
                                c->id, strerror(errno));
                        s->state = SS_CLOSED;
                        return WORK_ERROR;
                }
        } else {
                LOG_DBG("client %u successfully connected\n", c->id);
                s->state = SS_CONNECTED;
                s->active_events = s2->active_events = 0;
                s->monitored_events = s2->monitored_events = EPOLLIN | EPOLLOUT;
                client_epoll_set(c, s2, EPOLL_CTL_ADD, 0);
        }
  
        return WORK_OK;
}

static enum work_status client_connect_result(struct client *c)
{
        struct socket *s, *s2;
        int err = 0;
        socklen_t errlen = sizeof(err);
        int ret;

        if (c->from_family == AF_INET) {
                s = &c->sock[ST_SERVAL];
                s2 = &c->sock[ST_INET];
        } else {
                s2 = &c->sock[ST_SERVAL];
                s = &c->sock[ST_INET];
        }

        ret = getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
        
        if (ret == -1) {
                LOG_ERR("getsockopt: %s\n", strerror(errno));
                return WORK_ERROR;
        }
        
        switch (err) {
        case 0:
                s->monitored_events = s2->monitored_events = 
                        EPOLLIN | EPOLLOUT;
                s->active_events = s2->active_events = 0;
                s->state = SS_CONNECTED;
                client_epoll_set(c, s2, EPOLL_CTL_ADD, 0);
                LOG_DBG("client %u connected\n", c->id);
                break;
        case EINPROGRESS:
                LOG_DBG("client %u connection still in progress\n", c->id);
                break;
        default:
                s->state = SS_CLOSED;
                LOG_DBG("client %u connection error\n", c->id);
                s->monitored_events = s2->monitored_events = 0;

                return WORK_ERROR;
        }
        
        return WORK_OK;
}

static enum work_status client_close(struct client *c)
{
        LOG_DBG("client %u exits, "
                "serval=%zu/%zu inet=%zu/%zu\n", 
                c->id, 
                c->sock[ST_SERVAL].bytes_read, 
                c->sock[ST_SERVAL].bytes_written,
                c->sock[ST_INET].bytes_read, 
                c->sock[ST_INET].bytes_written);

        c->is_garbage = 1;
        close(c->sock[ST_SERVAL].fd);
        close(c->sock[ST_INET].fd);
        close(c->splicefd[0]);
        close(c->splicefd[1]);

        return WORK_OK;
}

static void signal_handler(int sig)
{
        LOG_DBG("signal %u caught!\n", sig);

        if (sig == SIGKILL || sig == SIGTERM)
                signal_raise_val(&main_signal, SIGNAL_EXIT);
}

static void garbage_collect_clients(void)
{
        struct client *c, *tmp;

        list_for_each_entry_safe(c, tmp, &client_list, lh) {
                if (c->is_garbage) {
                        LOG_DBG("garbage collecting client %u\n", c->id);
                        list_del(&c->lh);
                        client_free(c);
                }
        }
}

static void cleanup_clients(void)
{
        while (!list_empty(&client_list)) {
                struct client *c;

                c = list_first_entry(&client_list, struct client, lh);
                list_del(&c->lh);
                LOG_DBG("cleaning up client %u\n", c->id);
                client_free(c);
        }
}

static int create_server_sock(sockaddr_generic_t *addr)
{
        socklen_t addrlen = 0;
        int sock, ret = 0;               

	sock = socket(addr->sa.sa_family, SOCK_STREAM, 0);

	if (sock == -1) {
		LOG_ERR("socket: %s\n", strerror(errno));
                return -1;
	}
        
        switch (addr->sa.sa_family) {
        case AF_INET:
                ret = 1;
                ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 
                                 &ret, sizeof(ret));
                
                if (ret == -1) {
                        LOG_ERR("Could not set SO_REUSEADDR - %s\n",
                                strerror(errno));
                }
                addrlen = sizeof(addr->in);
                break;
        case AF_SERVAL:
                addrlen = sizeof(addr->sv);
                break;
        default:
                close(sock);
                LOG_ERR("Bad address family %ud\n", addr->sa.sa_family);
                return -1;
        }

        ret = bind(sock, &addr->sa, addrlen);

        if (ret == -1) {
		LOG_ERR("bind: %s\n", strerror(errno));
                goto failure;
	}

        ret = listen(sock, 10);

        if (ret == -1) {
                LOG_ERR("listen: %s\n", strerror(errno));
                goto failure;
        }

        return sock;
 failure:
        close(sock);

        return -1;
}

static struct client *accept_client(int sock, int port, 
                                    int cross_translate)
{
        sockaddr_generic_t addr;
        socklen_t addrlen = sizeof(addr);
        int client_sock;
        struct client *c;
#if defined(ENABLE_DEBUG)
        char ip[18];
#endif
        client_sock = accept(sock, &addr.sa, &addrlen);
        
        if (client_sock == -1) {
                switch (errno) {
                case EINTR:
                        /* This means we should exit
                         * (ctrl-c) */
                        break;
                default:
                        /* Other error, exit anyway */
                        LOG_ERR("accept: %s\n",
                                strerror(errno));
                }
                return NULL;
        }

        if (addr.sa.sa_family == AF_SERVAL) {
                /* Serval accept() could also returns IP appended after
                   serviceID */
                
                inet_ntop(AF_INET, &addr.sv_in.in.sin_addr, ip, 18);
                /* Only make serviceID visible */
                addrlen = sizeof(addr.sv);
        } else {
                inet_ntop(AF_INET, &addr.in.sin_addr, ip, 18);
        }

        c = client_create(client_sock, &addr.sa, 
                          addrlen, cross_translate);

        if (!c) {
                LOG_ERR("Could not create client, family=%d\n", 
                        addr.sa.sa_family);
                goto err;
        }

        LOG_DBG("client %u %s from %s addrlen=%u fd=%d\n", 
                c->id, family_to_str(addr.sa.sa_family), ip,
                addrlen, client_sock);

        c->translator_port = port;

        list_add_tail(&c->lh, &client_list);
        
        /* Make a note in our client log */
        if (addr.sa.sa_family == AF_INET && log_is_open(&logh)) {
                struct hostent *h;
                char buf[18];
                
                /* Cast to const char * to quell compiler on Android */
                h = gethostbyaddr((const char *)&addr.in.sin_addr, 4, AF_INET);
                
                log_write_line(&logh, "c %s %s",
                               inet_ntop(AF_INET, &addr.in.sin_addr, 
                                         buf, sizeof(buf)),
                               h ? h->h_name : "unknown hostname");
        }
        
        return c;       
 err:
        close(client_sock);
        return NULL;
}

#define MAX_WORKERS 20
static struct worker *workers;
static unsigned int num_workers = 4;

static int start_workers(unsigned int num)
{
        unsigned int i = 0;
        
        LOG_DBG("Creating %u workers\n", num);

        workers = malloc(sizeof(struct worker) * num);
        
        if (!workers)
                return -1;
        
        memset(workers, 0, sizeof(struct worker) * num);

        for (i = 0; i < num; i++) {
                struct worker *w = &workers[i];
                int ret;

                w->id = i;
                
                LOG_DBG("Starting worker %u\n", i);

                ret = pthread_create(&w->thr, NULL, worker_thread, w);
                
                if (ret != 0) {
                        LOG_ERR("pthread_create: %s\n",
                                strerror(errno));
                        return -1;
                }
        }

        return 0;
}

static void stop_workers(void)
{
        unsigned int i;

        worker_running = 0;
        pthread_cond_broadcast(&work_cond);

        for (i = 0; i < num_workers; i++) {
                if (workers[i].running) {
                        LOG_DBG("joining with worker %u\n", i);
                        pthread_join(workers[i].thr, NULL);
                }
        }
        free(workers);
}

static void schedule_client(struct client *c)
{
        if (c->is_scheduled)
                return;

        c->is_scheduled = 1;
        /* LOG_DBG("client %u scheduled\n", c->id); */
        pthread_mutex_lock(&work_mutex);
        list_add_tail(&c->wq, &workq);
        pthread_mutex_unlock(&work_mutex);
        pthread_cond_signal(&work_cond);        
}

static void check_socket_events(struct client *c, struct socket *s, 
                                unsigned int events)
{
        struct socket *s2;
        
        if (s->state == SS_CLOSED)
                return;

        if (s == &c->sock[ST_INET])
                s2 = &c->sock[ST_SERVAL];
        else
                s2 = &c->sock[ST_INET];
        /*
        LOG_DBG("s(fd=%d) state=%s events[R=%d W=%d] "
                "active[R=%d W=%d] monitored[R=%d W=%d] "
                "s2(fd=%d) active[R=%d W=%d] monitored[R=%d W=%d]\n",
                s->fd, 
                socket_state_str[s->state],
                (events & EPOLLIN) > 0,
                (events & EPOLLOUT) > 0,
                (s->active_events & EPOLLIN) > 0, 
                (s->active_events & EPOLLOUT) > 0,
                (s->monitored_events & EPOLLIN) > 0, 
                (s->monitored_events & EPOLLOUT) > 0,
                s2->fd, 
                (s2->active_events & EPOLLIN) > 0, 
                (s2->active_events & EPOLLOUT) > 0,
                (s2->monitored_events & EPOLLIN) > 0, 
                (s2->monitored_events & EPOLLOUT) > 0);
        */

        if (events & EPOLLIN) {
                if (s2->active_events & EPOLLOUT) {
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

        if (events & EPOLLOUT) {
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

void rearm_clients(void)
{
        struct client *c, *tmp;

        list_for_each_entry_safe(c, tmp, &client_list, lh) {
                if (!c->is_garbage && !c->is_scheduled)
                        client_epoll_set_all(c, EPOLL_CTL_MOD, EPOLLONESHOT);
        }
}

#define MAX_EVENTS 10
#define GC_TIMEOUT 3000

enum translator_mode {
        DUAL_MODE = 0,
        INET_ONLY_MODE,
        SERVAL_ONLY_MODE,
};

int run_translator(unsigned short port,
                   struct sockaddr_sv *sv,
                   int cross_translate, 
                   unsigned int mode)
{
	struct sigaction action;
	int inet_sock, serval_sock = -1, ret = 0, running = 1, sig_fd;
        struct epoll_event ev, events[MAX_EVENTS];
        int gc_timeout = GC_TIMEOUT;
        sockaddr_generic_t addr;

        memset(&action, 0, sizeof(struct sigaction));
        action.sa_handler = signal_handler;
        
	/* The server should shut down on these signals. */
        sigaction(SIGTERM, &action, 0);
	sigaction(SIGHUP, &action, 0);
	sigaction(SIGINT, &action, 0);
        sigaction(SIGPIPE, &action, 0);
        
        signal_init(&main_signal);
        sig_fd = signal_get_fd(&main_signal);

        epollfd = epoll_create(10);
        
        if (epollfd == -1) {
                LOG_ERR("Could not create epoll fd: %s\n", 
                        strerror(errno));
                goto err_epoll_create;
        }
        
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN;
        ev.data.ptr = &sig_fd;

        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sig_fd, &ev) == -1) {
                LOG_ERR("Could not add signal to epoll events: %s\n",
                        strerror(errno));
                goto err_epoll_create;
        }
        
        if (mode == INET_ONLY_MODE || mode == DUAL_MODE) {
                memset(&addr, 0, sizeof(addr));
                addr.in.sin_family = AF_INET;
                addr.in.sin_addr.s_addr = INADDR_ANY;
                addr.in.sin_port = htons(port);

                inet_sock = create_server_sock(&addr);
                
                if (inet_sock == -1) {
                        LOG_ERR("could not create AF_INET server sock\n");
                        ret = inet_sock;
                        goto err_inet_sock;
                }
                
                /* Set events. EPOLLERR and EPOLLHUP may always be returned,
                 * even if not set here */
                memset(&ev, 0, sizeof(ev));
                ev.events = EPOLLIN;
                ev.data.ptr = &inet_sock;
                
                ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, inet_sock, &ev);

                if (ret == -1) {
                        LOG_ERR("epoll_ctl INET listen: %s\n",
                                strerror(errno));
                        goto err_epoll_ctl_inet;
                }
                LOG_DBG("listening on port %u\n", port);
        }

        if (mode == SERVAL_ONLY_MODE || mode == DUAL_MODE) {
                memset(&addr, 0, sizeof(addr));
                memcpy(&addr.sv, sv, sizeof(*sv));
                addr.sv.sv_family = AF_SERVAL;

                /* Listen to a prefix, since, in case of cross
                 * translation, the incoming connections will have a
                 * serviceID with the lower order bits being the IP
                 * address and port. */
                if (cross_translate && sv->sv_prefix_bits == 0)
                        addr.sv.sv_prefix_bits = 128;
                
                serval_sock = create_server_sock(&addr);              
                
                if (serval_sock == -1) {
                        LOG_ERR("could not create AF_SERVAL server sock\n");
                        ret = serval_sock;
                        goto err_serval_sock;
                }
                
                memset(&ev, 0, sizeof(ev));
                ev.events = EPOLLIN;
                ev.data.ptr = &serval_sock;
        
                ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, serval_sock, &ev);

                if (ret == -1) {
                        LOG_ERR("epoll_ctl SERVAL listen sock: %s\n",
                                strerror(errno));
                        goto err_epoll_ctl_serval;
                }
                LOG_DBG("listening on serviceID %s:%u\n",
                        service_id_to_str(&sv->sv_srvid), 
                        sv->sv_prefix_bits);
        }

        ret = start_workers(num_workers);
        
        if (ret == -1)
                goto err_workers;

        LOG_DBG("translator running\n");

        while (running) {
                struct timespec prev_time, now;
                int nfds, i;

                clock_gettime(CLOCK_REALTIME, &prev_time);

                nfds = epoll_wait(epollfd, events, 
                                  MAX_EVENTS, gc_timeout);
                
                clock_gettime(CLOCK_REALTIME, &now);

                timespec_sub(&now, &prev_time);
                
                gc_timeout = GC_TIMEOUT - ((now.tv_sec * 1000) + 
                                           (now.tv_nsec / 1000000));

                /* LOG_DBG("gc_timeout=%d\n", gc_timeout); */
                
                if (nfds == -1) {
                        if (errno == EINTR) {
                                /* Just exit */
                        } else {
                                LOG_ERR("epoll_wait: %s\n",
                                        strerror(errno));
                                ret = -1;
                        }
                        break;
                } else if (nfds == 0 || gc_timeout < 50) {
                        garbage_collect_clients();
                        gc_timeout = GC_TIMEOUT;
                        continue;
                } 

                for (i = 0; i < nfds; i++) {
                        /* We can cast to struct socket here since we
                           know fd is first member of the struct */
                        struct socket *s = (struct socket *)events[i].data.ptr;

                        if (s->fd == inet_sock || s->fd == serval_sock) {
                                struct client *c;                                

                                c = accept_client(s->fd, port, cross_translate); 
                                
                                if (!c) {
                                        LOG_ERR("client accept failure\n");
                                } else {
                                        client_add_work(c, client_connect);
                                        schedule_client(c);
                                }
                        } else if (s->fd == sig_fd) {
                                int val;

                                signal_clear_val(&main_signal, &val);
                                
                                switch (val) {
                                case SIGNAL_EXIT:
                                        running = 0;
                                        break;
                                case SIGNAL_EPOLL_REARM:
                                        /* Just indicates that we should rearm */
                                default:
                                        break;
                                }
                        } else {
                                struct client *c = s->c;

                                s->active_events |= events[i].events;
                                check_socket_events(c, s, events[i].events);

                                if (c->num_work) {
                                        schedule_client(c);
                                }
                        }
                }
                rearm_clients();
        }
        LOG_DBG("Translator exits.\n");
err_workers:
        stop_workers();
        LOG_DBG("Cleaning up clients\n");
        cleanup_clients();
 err_epoll_ctl_serval:
        if (serval_sock > 0)
                close(serval_sock);
 err_epoll_ctl_inet:
 err_serval_sock:
        if (inet_sock > 0)
                close(inet_sock);
 err_inet_sock:
        close(epollfd);
 err_epoll_create:
        signal_destroy(&main_signal);

        return ret;
}

#if !defined(OS_ANDROID)

static void print_usage(void)
{
        printf("Usage: translator [ OPTIONS ]\n");
        printf("where OPTIONS:\n");
        printf("\t-d, --daemon\t\t\t run in the background as a daemon.\n");
        printf("\t-f, --file-limit LIMIT\t\t set the maximum number of open file descriptors.\n");
        printf("\t-p, --port PORT\t\t\t port to listen on.\n");
        printf("\t-s, --serviceid SERVICE_ID\t\t serviceID to listen on.\n");
        
        printf("\t-l, --log LOG_FILE\t\t file to write client IPs to.\n");
        printf("\t-w, --workers NUM_WORKERS\t number of worker threads (default %u).\n", 
               num_workers);
        printf("\t-io, --inet-only\t\t listen only for AF_INET connections.\n");
        printf("\t-so, --serval-only\t\t listen only for AF_SERVAL connections.\n");
        printf("\t-x, --cross-translate\t\t allow connections from another AF_SERVAL->AF_INET.\n");
}

static int daemonize(void)
{
        int i, sid;
	FILE *f;

        /* check if already a daemon */
	if (getppid() == 1) 
                return -1; 
	
	i = fork();

	if (i < 0) {
		fprintf(stderr, "Fork error...\n");
                return -1;
	}
	if (i > 0) {
		//printf("Parent done... pid=%u\n", getpid());
                exit(EXIT_SUCCESS);
	}
	/* new child (daemon) continues here */
	
	/* Change the file mode mask */
	umask(0);
		
	/* Create a new SID for the child process */
	sid = setsid();
	
	if (sid < 0)
		return -1;
	
	/* 
	 Change the current working directory. This prevents the current
	 directory from being locked; hence not being able to remove it. 
	 */
	if (chdir("/") < 0) {
		return -1;
	}
	
	/* Redirect standard files to /dev/null */
	f = freopen("/dev/null", "r", stdin);

        if (!f) {
                LOG_ERR("stdin redirection failed\n");
        }

	f = freopen("/dev/null", "w", stdout);

        if (!f) {
                LOG_ERR("stdout redirection failed\n");
        }

	f = freopen("/dev/null", "w", stderr);

        if (!f) {
                LOG_ERR("stderr redirection failed\n");
        }

        return 0;
}

static int parse_serviceid(const char *str, struct sockaddr_sv *sv)
{
        int len;
        char *buf, *ptr, *id, *prefix = NULL;

        /* Allocate a non-const string buffer we can manipulate */
        buf = malloc(strlen(str) + 1);
        
        if (!buf)
                return -1;
        
        strcpy(buf, str);

        ptr = buf;

        if (buf[0] == '0' && buf[1] == 'x')
                ptr += 2;
        
        id = ptr;

        while (*ptr != ':' && *ptr != '\0')
                ptr++;
        
        if (*ptr == ':') {
                prefix = ptr + 1;
                *ptr = '\0';
        }
        
        len = strlen(id);
        
        if (len > 64)
                len = 64;
        
        if (serval_pton(id, &sv->sv_srvid) == -1) {
                free(buf);
                return -1;
        }

        if (prefix) {
                long bits = strtoul(prefix, &ptr, 10);

                if (*ptr == '\0' && *prefix != '\0') {
                        if (bits > 255)
                                bits = 0;
                        sv->sv_prefix_bits = bits & 0xff;
                }
        }

        free(buf);

        return 0;
}

int main(int argc, char **argv)
{       
        unsigned short port = DEFAULT_TRANSLATOR_PORT;
        const char *serviceid = DEFAULT_SERVICE_ID;
        int ret = 0, daemon = 0, cross_translate = 0;
        struct rlimit limit;
        rlim_t file_limit = 0;
        unsigned int mode = DUAL_MODE;
        struct sockaddr_sv sv;

        memset(&sv, 0, sizeof(sv));
        sv.sv_family = AF_SERVAL;

        argc--;
	argv++;
        
	while (argc) {
                if (strcmp(argv[0], "-p") == 0 ||
		    strcmp(argv[0], "--port") == 0) {
                        if (argc == 1) {
                                print_usage();
                                goto fail;
                        }
                        
                        port = atoi(argv[1]);
                        argv++;
                        argc--;
                } else if (strcmp(argv[0], "-s") == 0 ||
                           strcmp(argv[0], "--serviceid") == 0) {
                        if (argc == 1) {
                                print_usage();
                                goto fail;
                        }
                        serviceid = argv[1];
                        argv++;
                        argc--;
                } else if (strcmp(argv[0], "-h") == 0 ||
                           strcmp(argv[0], "--help") ==  0) {
                        print_usage();
                        goto fail;
                } else if (strcmp(argv[0], "-f") == 0 ||
                           strcmp(argv[0], "--file-limit") ==  0) {
                        if (argc == 1) {
                                print_usage();
                                goto fail;
                        }
                        file_limit = atoi(argv[1]);
                } else if (strcmp(argv[0], "-d") == 0 ||
                           strcmp(argv[0], "--daemon") ==  0) {
                        daemon = 1;
                } else if (strcmp(argv[0], "-x") == 0 ||
                           strcmp(argv[0], "--cross-translate") ==  0) {
                        cross_translate = 1;
                } else if (strcmp(argv[0], "-io") == 0 ||
                           strcmp(argv[0], "--inet-only") ==  0) {
                        mode = INET_ONLY_MODE;
                } else if (strcmp(argv[0], "-so") == 0 ||
                           strcmp(argv[0], "--serval-only") ==  0) {
                        mode = SERVAL_ONLY_MODE;
                } else if (strcmp(argv[0], "-w") == 0 ||
                           strcmp(argv[0], "--workers") ==  0) {
                        unsigned long n;
                        char *tmp;

                        if (argc == 1) {
                                print_usage();
                                goto fail;
                        }
                        n = strtoul(argv[1], &tmp, 10);

                        if (!(*argv[1] != '\0' && *tmp == '\0')) {
                                print_usage();
                                goto fail;
                        }
                        if (n > MAX_WORKERS) {
                                fprintf(stderr, "Too many worker threads (max %u)\n",
                                        MAX_WORKERS);
                                goto fail;
                        }
                        num_workers = n;
                } else if (strcmp(argv[0], "-l") == 0 ||
                           strcmp(argv[0], "--log") ==  0) {
                        if (argc == 1 || log_is_open(&logh)) {
                                print_usage();
                                goto fail;
                        }
                        ret = log_open(&logh, argv[1]);

                        if (ret == -1) {
                                LOG_ERR("bad log file %s\n",
                                        argv[1]);
                                goto fail;
                        }

                        LOG_DBG("Writing client log to '%s'\n",
                                argv[1]);
                        argv++;
                        argc--;
                }

		argc--;
		argv++;
	}	


        if (mode != INET_ONLY_MODE && 
            parse_serviceid(serviceid, &sv) != 0) {
                print_usage();
                goto fail;
        }

        if (daemon) {
                LOG_DBG("going daemon...\n");
                ret = daemonize();
                
                if (ret < 0) {
                        LOG_ERR("Could not daemonize\n");
                        return ret;
                } 
        }

        ret = getrlimit(RLIMIT_NOFILE, &limit);
        
        if (ret == -1) {
                LOG_ERR("Could not get file limit: %s\n", strerror(errno));
        } else {
                /* Increase file limit as much as we can. If we are
                 * root, we might be able to set a higher limit. */
                if (file_limit > 0) 
                        limit.rlim_cur = limit.rlim_max = file_limit;
                else
                        limit.rlim_cur = limit.rlim_max;
                
                LOG_DBG("Setting open file limit to %lu\n",
                        limit.rlim_cur);
                
                ret = setrlimit(RLIMIT_NOFILE, &limit);

                if (ret == -1) {
                        LOG_ERR("could not set file limit: %s\n", 
                                strerror(errno));
                }
        }
        
        ret = run_translator(port, &sv, cross_translate, mode);
fail:
        if (log_is_open(&logh))
                log_close(&logh);

	return ret;
}

#endif /* OS_ANDROID */
