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

struct socket {
        int fd; /* Must be first */
        enum socket_state state;
        struct client *c;
        uint32_t events;
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
        struct signal exit_signal;
};

struct translator_init_pkt {
        struct in_addr addr;
        uint16_t port;
} __attribute__((packed));

#define DEFAULT_TRANSLATOR_PORT 8080
static const char *translator_service_name = "translator.serval-arch.org";
static LOG_DEFINE(logh);
struct signal exit_signal;
static LIST_HEAD(client_list);
static int epollfd = -1;

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


static enum work_status work_translate(struct socket *from, 
                                       struct socket *to,
                                       int splicefd[2])
{
        ssize_t ret;
        size_t readlen, nbytes = 0;
        enum work_status status = WORK_OK;
        int bytes_queued = 0;
        
        ret = ioctl(to->fd, TIOCOUTQ, &bytes_queued);

        if (ret == -1) {
                LOG_ERR("ioctl error - %s\n", strerror(errno));
                return WORK_ERROR;
        }

        readlen = to->sndbuf - bytes_queued;


        /* LOG_DBG("translating %zu bytes from %d to %d\n", 
           readlen, from->fd, to->fd); */

        if (readlen == 0) {
                /* There wasn't enough space in send buffer of the
                 * socket we are writing to, we need to stop monitor
                 * readability on the "from" socket and instead watch
                 * for writability on the "to" socket. */
                from->events &= ~EPOLLIN;
                to->events |= EPOLLOUT;
                /*
                LOG_DBG("readlen 0, waiting for readability from->events=%u to->events=%u\n",
                        from->events, to->events);
                */
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
        /* LOG_DBG("splice2 %zu bytes\n", nbytes); */
 out:
        to->events &= ~EPOLLOUT;
        from->events |= EPOLLIN;
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

static int client_epoll_set(struct client *c, int op)
{               
        unsigned int i;
        int ret;

        if (c->is_garbage)
                return -1;

        for (i = 0; i < 2; i++) {
                struct epoll_event ev;

                memset(&ev, 0, sizeof(ev));
                ev.events = c->sock[i].events;
                ev.data.ptr = &c->sock[i];
                
                /*
                  LOG_DBG("Watching events %u on sock %d\n",
                        ev.events, c->sock[i].fd);
                */
                ret = epoll_ctl(epollfd, op, c->sock[i].fd, &ev);
                
                if (ret == -1) {
                        LOG_ERR("epoll_ctl op=%d fd=%d: %s\n",
                                op, c->sock[i].fd, strerror(errno));
                        break;
                }
        }

        return ret;
}

static int service_to_sockaddr_in(struct service_id *srvid, struct sockaddr_in *in)
{
        size_t i = strlen(srvid->s_sid);
        size_t n = 0;

        while (i) {
                if (srvid->s_sid[i] == '-') {
                        in->sin_port = htons(atoi(&srvid->s_sid[i+1]));
                        n = i;
                } else if (srvid->s_sid[i] == '.') {
                        char ip[18];
                        
                        if (n == 0)
                                return -1;
                        
                        strncpy(ip, &srvid->s_sid[i+1], n - i);
               
                        if (inet_pton(AF_INET, ip, &in->sin_addr) != 1)
                                return -1;
                        return 0;
                }

                i--;
        }

        return -1;
}

struct client *client_create(int sock, struct sockaddr *sa, 
                             socklen_t salen)
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
        c->sock[0].c = c->sock[1].c = c;
        INIT_LIST_HEAD(&c->lh);
        INIT_LIST_HEAD(&c->wq);
        signal_init(&c->exit_signal);
        
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
                c->sock[ST_INET].events = 0;
                c->sock[ST_SERVAL].state = SS_CLOSED;
                c->sock[ST_SERVAL].events = EPOLLOUT;

                c->sock[ST_SERVAL].fd = socket(AF_SERVAL, SOCK_STREAM, 0);
                
                if (c->sock[ST_SERVAL].fd == -1) {
                        LOG_ERR("serval socket: %s\n",
                                strerror(errno));
                        goto fail_sock;
                }
        } else if (c->from_family == AF_SERVAL) {
                /* We're translating from AF_SERVAL to AF_INET */
                c->sock[ST_SERVAL].fd = sock;
                memcpy(&c->sock[ST_SERVAL].addr, sa, 
                       sizeof(struct sockaddr_sv));
                c->sock[ST_SERVAL].addrlen = sizeof(struct sockaddr_sv);
                c->sock[ST_SERVAL].state = SS_CONNECTED;
                c->sock[ST_SERVAL].events = 0;
                c->sock[ST_INET].state = SS_CLOSED;
                c->sock[ST_INET].events = EPOLLOUT;

                /* The end of the serviceID contains the original port
                   and IP. */ 
                c->sock[ST_INET].addr.in.sin_family = AF_INET;
                ret = service_to_sockaddr_in(&c->sock[ST_SERVAL].addr.sv.sv_srvid,
                                             &c->sock[ST_INET].addr.in);

                if (ret == -1) {
                        LOG_ERR("Could not extract IP and port from serviceID %s\n",
                                service_id_to_str(&c->sock[ST_SERVAL].addr.sv.sv_srvid));
                }
                                              
                c->sock[ST_INET].fd = socket(AF_INET, SOCK_STREAM, 0);
                
                if (c->sock[ST_INET].fd == -1) {
                        LOG_ERR("inet socket: %s\n",
                                strerror(errno));
                        goto fail_sock;
                }
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
        /* Add the file descriptors to the epoll set just to avoid
         * complaints when we call EPOLL_CTL_DEL when we schedule the
         * client later */
        client_epoll_set(c, EPOLL_CTL_ADD);

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
        signal_destroy(&c->exit_signal);
        return NULL;
}

static void client_free(struct client *c)
{
        signal_destroy(&c->exit_signal);
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
                        client_epoll_set(c, EPOLL_CTL_ADD);
        }
        
        LOG_DBG("Worker %u exits\n", w->id);

        return NULL;
}

static int service_id_to_ip(struct service_id *srvid, struct in_addr *addr)
{
        struct addrinfo hints, *ai, *ai_it;
        const char *port = NULL;
        char host[128];
        int ret;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = 0;
        
        serval_ntop(srvid, host, sizeof(host));
        
        ret = getaddrinfo(host, port, &hints, &ai);

        if (ret != 0) {
                LOG_ERR("%s", gai_strerror(ret));
                return ret;
        }

        ret = -1;

        for (ai_it = ai; ai_it; ai_it = ai_it->ai_next) {
                if (ai_it->ai_family == AF_INET) {
                        char buf[20];
                        ret = 0;
                        LOG_DBG("found ip %s\n", 
                                inet_ntop(AF_INET, &ai_it->ai_addr, buf, 20));
                        memcpy(addr, ai_it->ai_addr, sizeof(struct in_addr));
                        break;
                }
        }

        freeaddrinfo(ai);                                

        return ret;
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

                if (c->cross_translate) {
                        char buf[SERVICE_ID_MAX_LEN+1];
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
                        sprintf(buf, "%s-%u.%s",
                                ipstr,
                                ntohs(c->sock[ST_INET].addr.in.sin_port), 
                                translator_service_name);
                        serval_pton(buf, &addr.sv.sv_srvid);
                } else {
                        serval_pton(translator_service_name, 
                                    &addr.sv.sv_srvid);
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
       
        ret = connect(s->fd, &addr.sa, addrlen);

        if (ret == -1) {
                if (errno == EINPROGRESS) {
                        s->state = SS_CONNECTING;
                        s->events = EPOLLOUT;
                } else {
                        LOG_ERR("client %u connect failed: %s\n",
                                c->id, strerror(errno));
                        return WORK_ERROR;
                }
        } else {
                LOG_DBG("client %u successfully connected\n", c->id);
                s->state = SS_CONNECTED;
                s->events = s2->events = EPOLLIN;
        }
  
        return WORK_OK;
}

static enum work_status client_connect_result(struct client *c)
{
        struct socket *s = c->from_family == AF_INET ?
                &c->sock[ST_SERVAL] : &c->sock[ST_INET];
        int err = 0;
        socklen_t errlen = sizeof(err);
        int ret;

        ret = getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
        
        if (ret == -1) {
                LOG_ERR("getsockopt: %s\n", strerror(errno));
                return WORK_ERROR;
        }
        
        switch (err) {
        case 0:
                c->sock[ST_INET].events = c->sock[ST_SERVAL].events = EPOLLIN;
                s->state = SS_CONNECTED;
                LOG_DBG("client %u connected\n", c->id);
                break;
        case EINPROGRESS:
                LOG_DBG("client %u connection still in progress\n", c->id);
                break;
        default:
                s->state = SS_CLOSED;
                LOG_DBG("client %u connection error\n", c->id);
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
                signal_raise(&exit_signal);
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

static int create_server_sock(int family, unsigned short port, 
                              int cross_translate)
{
        sockaddr_generic_t addr;
        socklen_t addrlen = 0;
        int sock, ret = 0;               

	sock = socket(family, SOCK_STREAM, 0);

	if (sock == -1) {
		LOG_ERR("inet socket: %s\n",
			strerror(errno));
                return -1;
	}
        
        memset(&addr, 0, sizeof(addr));

        if (family == AF_INET) {
                ret = 1;
                ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 
                                 &ret, sizeof(ret));
                
                if (ret == -1) {
                        LOG_ERR("Could not set SO_REUSEADDR - %s\n",
                                strerror(errno));
                }
                addr.in.sin_family = AF_INET;
                addr.in.sin_addr.s_addr = INADDR_ANY;
                addr.in.sin_port = htons(port);
                addrlen = sizeof(addr.in);
        } else if (family == AF_SERVAL) {
                addr.sv.sv_family = AF_SERVAL;
                
                
                if (cross_translate) {
                        /* Listen to a "prefix", since, in case of cross
                         * translation, the incoming connections will have a
                         * serviceID ending with the IP address and port. */

                        char buf[SERVICE_ID_MAX_LEN+1];
                        snprintf(buf, sizeof(buf), "*.%s", translator_service_name);
                        serval_pton(buf, &addr.sv.sv_srvid);
                } else {
                        serval_pton(translator_service_name, 
                                    &addr.sv.sv_srvid);
                }
                addrlen = sizeof(addr.sv);
        } else {
                close(sock);
                return -1;
        }

        ret = bind(sock, &addr.sa, addrlen);

        if (ret == -1) {
		LOG_ERR("inet bind: %s\n",
			strerror(errno));
                goto failure;
	}

        ret = listen(sock, 10);

        if (ret == -1) {
                LOG_ERR("inet listen: %s\n",
			strerror(errno));
                goto failure;
        }

        return sock;
 failure:
        close(sock);

        return -1;
}

static struct client *accept_client(int sock, int port)
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

        c = client_create(client_sock, &addr.sa, addrlen);

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
        //LOG_DBG("client %u scheduling\n", c->id);
        client_epoll_set(c, EPOLL_CTL_DEL);
        pthread_mutex_lock(&work_mutex);
        list_add_tail(&c->wq, &workq);
        pthread_mutex_unlock(&work_mutex);
        pthread_cond_signal(&work_cond);        
}

/*
static void print_events(struct socket *s, uint32_t events)
{
        struct client *c = s->c;

        if (s == &c->sock[ST_INET]) {
                LOG_DBG("client %u ST_INET state=%u R=%d W=%d\n",
                        c->id, s->state, (events & EPOLLIN) > 0, (events & EPOLLOUT) > 0);
        } else {
                LOG_DBG("client %u ST_SERVAL state=%u R=%d W=%d\n",
                        c->id, s->state, (events & EPOLLIN) > 0, (events & EPOLLOUT) > 0);
        }
}
*/

#define MAX_EVENTS 10
#define GC_TIMEOUT 3000

int run_translator(int family, unsigned short port, int cross_translate)
{
	struct sigaction action;
	int sock, ret = 0, running = 1, sig_fd;
        struct epoll_event ev, events[MAX_EVENTS];
        int gc_timeout = GC_TIMEOUT;

        memset(&action, 0, sizeof(struct sigaction));
        action.sa_handler = signal_handler;
        
	/* The server should shut down on these signals. */
        sigaction(SIGTERM, &action, 0);
	sigaction(SIGHUP, &action, 0);
	sigaction(SIGINT, &action, 0);
        sigaction(SIGPIPE, &action, 0);
        
        signal_init(&exit_signal);
        sig_fd = signal_get_fd(&exit_signal);

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
        
        sock = create_server_sock(family, port, cross_translate);

        if (sock == -1) {
                LOG_ERR("could not create AF_INET server sock\n");
                ret = sock;
                goto err_server_sock;
        }
        
        /* Set events. EPOLLERR and EPOLLHUP may always be returned,
         * even if not set here */
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN;
        ev.data.ptr = &sock;
        
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock, &ev) == -1) {
                LOG_ERR("Could not add listen sock to epoll events: %s\n",
                        strerror(errno));
                goto err_epoll_ctl;
        }

        ret = start_workers(num_workers);
        
        if (ret == -1)
                goto err_workers;

        LOG_DBG("%s to %s translator running\n", 
                family_to_str(family), 
                family_to_str(family == AF_INET ? AF_SERVAL : AF_INET));
        
        while (running) {
                struct timespec prev_time, now;
                int nfds, i;

                clock_gettime(CLOCK_REALTIME, &prev_time);

                nfds = epoll_wait(epollfd, events, 
                                  MAX_EVENTS, gc_timeout);
                
                clock_gettime(CLOCK_REALTIME, &now);

                timespec_sub(&now, &prev_time);
                
                gc_timeout = GC_TIMEOUT - ((now.tv_sec * 1000) + (now.tv_nsec / 1000000));

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

                        if (s->fd == sock) {
                                struct client *c;
                                
                                c = accept_client(sock, port); 
                                
                                if (!c) {
                                        LOG_ERR("client accept failure\n");
                                } else {
                                        c->cross_translate = (cross_translate == 1);
                                        client_add_work(c, client_connect);
                                        schedule_client(c);
                                }
                        } else if (s->fd == sig_fd) {
                                running = 0;
                        } else {
                                struct client *c = s->c;
                                uint32_t monitored_events = 
                                        EPOLLIN | EPOLLERR | EPOLLHUP ; 
                                
                                /* print_events(s, events[i].events); */

                                if ((&c->sock[ST_INET] == s && 
                                     (events[i].events & monitored_events)) ||
                                    (&c->sock[ST_SERVAL] == s && 
                                     (events[i].events & EPOLLOUT))) {
                                        if (s->state == SS_CONNECTING)
                                                client_add_work(c, client_connect_result);
                                        else
                                                client_add_work(c, work_inet_to_serval);
                                } else if ((&c->sock[ST_SERVAL] == s && 
                                            (events[i].events & monitored_events)) ||
                                           (&c->sock[ST_INET] == s && 
                                            (events[i].events & EPOLLOUT))) {
                                        if (s->state == SS_CONNECTING)
                                                client_add_work(c, client_connect_result);
                                        else
                                                client_add_work(c, work_serval_to_inet);
                                }
                                
                                if (c->num_work) {
                                        schedule_client(c);
                                }
                        }
                }
        }
        LOG_DBG("Translator exits.\n");
 err_workers:
        stop_workers();
        LOG_DBG("Cleaning up clients\n");
        cleanup_clients();
 err_epoll_ctl:
	close(sock);
 err_server_sock:
        close(epollfd);
 err_epoll_create:
        signal_destroy(&exit_signal);

        return ret;
}

#if !defined(OS_ANDROID)

static void print_usage(void)
{
        printf("Usage: translator [ OPTIONS ]\n");
        printf("where OPTIONS:\n");
        printf("\t-d, --daemon\t\t\t run in the background as a daemon.\n");
        printf("\t-p, --port PORT\t\t\t port/serviceID to listen on.\n");
        printf("\t-l, --log LOG_FILE\t\t file to write client IPs to.\n");
        printf("\t-s, --serval\t\t\t run an AF_SERVAL to AF_INET translator.\n");
        printf("\t-w, --workers NUM_WORKERS\t number of worker threads (default %u).\n", 
               num_workers);
        printf("\t-x, --cross-translate\t\t an AF_SERVAL->AF_INET translator connects to "
               "an AF_SERVAL->AF_INET translator. Both need this option set.\n");
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

int main(int argc, char **argv)
{       
        unsigned short port = DEFAULT_TRANSLATOR_PORT;
        int ret = 0, family = AF_INET, daemon = 0;
        int cross_translate = 0;

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
                } else if (strcmp(argv[0], "-h") == 0 ||
                           strcmp(argv[0], "--help") ==  0) {
                        print_usage();
                        goto fail;
                } else if (strcmp(argv[0], "-s") == 0 ||
                           strcmp(argv[0], "--serval") ==  0) {
                        /* Run a SERVAL to INET translator */
                        family = AF_SERVAL;
                } else if (strcmp(argv[0], "-d") == 0 ||
                           strcmp(argv[0], "--daemon") ==  0) {
                        daemon = 1;
                } else if (strcmp(argv[0], "-x") == 0 ||
                           strcmp(argv[0], "--cross-translate") ==  0) {
                        cross_translate = 1;
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

        if (daemon) {
                LOG_DBG("going daemon...\n");
                ret = daemonize();
                
                if (ret < 0) {
                        LOG_ERR("Could not daemonize\n");
                        return ret;
                } 
        }

        ret = run_translator(family, port, cross_translate);
fail:
        if (log_is_open(&logh))
                log_close(&logh);

	return ret;
}

#endif /* OS_ANDROID */
