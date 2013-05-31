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
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <common/signal.h>
#include <common/list.h>
#define ENABLE_DEBUG 1
#include <common/debug.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <limits.h>
#include <linux/netfilter_ipv4.h>
#include <fcntl.h>
#include "translator.h"
#include "client.h"
#include "worker.h"

static unsigned int client_num = 0;

#if defined(ENABLE_DEBUG)
const char *socket_state_str[] = {
        "INIT",
        "CONNECTING",
        "CONNECTED",
        "CLOSED"
};
#endif

static int fd_set_nonblock(int fd)
{
        int flags, ret = 0;
        
        flags = fcntl(fd, F_GETFL, ret);
        
        if (flags == -1) {
                LOG_ERR("fctnl(F_GETFL): %s\n", strerror(errno));
                return -1;
        }
        
        ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        
        if (ret == -1) {
                LOG_ERR("fctnl(F_SETFL): %s\n", strerror(errno));
        } 

        return ret;
}

int client_epoll_set(struct client *c, struct socket *s, 
                     int op, unsigned int extra_event)
{
        struct epoll_event ev;
        int ret = 0;
        
        memset(&ev, 0, sizeof(ev));
        ev.events = s->monitored_events | extra_event;
        ev.data.ptr = s;

        LOG_MAX("client=%u op=%s fd=%d events[R=%d W=%d H=%d]\n",
                c->id,
                EPOLL_CTL_MOD == op ?                                
                "EPOLL_CTL_MOD" :
                (EPOLL_CTL_ADD == op ? "EPOLL_CTL_ADD" : "EPOLL_CTL_DEL"),
                s->fd,
                (ev.events & EPOLLIN) > 0, 
                (ev.events & EPOLLOUT) > 0,
                (ev.events & EPOLLRDHUP) > 0);

        ret = epoll_ctl(c->w->epollfd, op, s->fd, &ev);
        
        if (ret == -1) {
                LOG_MAX("epoll_ctl op=%d fd=%d: %s\n",
                        op, s->fd, strerror(errno));
        }
        
        return ret;
}

int client_epoll_set_all(struct client *c, int op, 
                         unsigned int extra_event)
{               
        unsigned int i;
        int ret = 0;

        for (i = 0; i < 2; i++) {
                if (c->sock[i].state != SS_CLOSED) {
                        ret = client_epoll_set(c, &c->sock[i],
                                               op, extra_event);
                        
                        if (ret == -1)
                                break;
                }
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
        c->cross_translate = cross_translate == 1;
        c->sock[0].c = c->sock[1].c = c;
        INIT_LIST_HEAD(&c->lh);
        
        if (c->from_family == AF_INET) {
                /* We're translating from AF_INET to AF_SERVAL */
                c->sock[ST_INET].fd = sock;
                memcpy(&c->sock[ST_INET].addr, sa, 
                       sizeof(struct sockaddr_in));
                c->sock[ST_INET].addrlen = sizeof(struct sockaddr_in);
                c->sock[ST_INET].state = SS_CONNECTED;
                c->sock[ST_INET].monitored_events = EPOLLRDHUP;
                c->sock[ST_INET].active_events = 0;
                c->sock[ST_SERVAL].state = SS_INIT;
                c->sock[ST_SERVAL].monitored_events = EPOLLOUT;
                c->sock[ST_SERVAL].active_events = 0;

                c->sock[ST_SERVAL].fd = socket(AF_SERVAL, SOCK_STREAM, 0);
                
                if (c->sock[ST_SERVAL].fd == -1) {
                        LOG_ERR("serval socket: %s\n",
                                strerror(errno));
                        goto fail_sock;
                }
        } else if (c->from_family == AF_SERVAL) {
                struct sockaddr_sv sv;
                socklen_t svlen = sizeof(sv);

                /* We're translating from AF_SERVAL to AF_INET */
                c->sock[ST_SERVAL].fd = sock;
                memcpy(&c->sock[ST_SERVAL].addr, sa, 
                       sizeof(struct sockaddr_sv));
                c->sock[ST_SERVAL].addrlen = sizeof(struct sockaddr_sv);
                c->sock[ST_SERVAL].state = SS_CONNECTED;
                c->sock[ST_SERVAL].monitored_events = EPOLLRDHUP;
                c->sock[ST_SERVAL].active_events = 0;
                c->sock[ST_INET].state = SS_INIT;
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
        } else {
                LOG_ERR("Unsupported client family\n");
                goto fail_sock;
        }
        
        for (i = 0; i < 2; i++) {
                socklen_t len = sizeof(c->sock[i].sndbuf);

                ret = getsockopt(c->sock[i].fd, SOL_SOCKET, 
                                 SO_SNDBUF, &c->sock[i].sndbuf, 
                                 &len);
                
                if (ret == -1) {
                        LOG_ERR("getsockopt(sndbuf) - %s\n", strerror(errno));
                }
                

                ret = pipe(c->sock[i].splicefd);
                
                if (ret == -1) {
                        LOG_ERR("pipe: %s\n",
                                strerror(errno));
                        goto fail_post_sock;
                }

                ret = fd_set_nonblock(c->sock[i].splicefd[0]);

                if (ret == -1)
                        goto fail_post_sock;

                ret = fd_set_nonblock(c->sock[i].splicefd[1]);

                if (ret == -1)
                        goto fail_post_sock;
                
                ret = fd_set_nonblock(c->sock[i].fd);

                if (ret == -1)
                        goto fail_post_sock;
        }

        return c;

fail_post_sock:
        close(c->sock[0].splicefd[0]);
        close(c->sock[0].splicefd[1]);
        close(c->sock[1].splicefd[0]);
        close(c->sock[1].splicefd[1]);

        if (c->sock[1].fd == sock)
                close(c->sock[0].fd);
        else
                close(c->sock[1].fd);
 fail_sock:
        close(sock);
        free(c);
        return NULL;
}

void client_free(struct client *c)
{
        list_del_init(&c->lh);
        free(c);
}

int client_add_work(struct client *c, work_t work)
{
        if (c->num_work == MAX_WORK)
                return -1;
        
        c->work[c->num_work++] = work;
        return 0;
}

enum work_status client_connect(struct client *c)
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
        s->active_events = 0;
        ret = connect(s->fd, &addr.sa, addrlen);
        
        if (ret == -1) {
                if (errno == EINPROGRESS) {
                        s->monitored_events = EPOLLOUT;
                        LOG_DBG("client %u fd=%d connection in progress...\n",
                                c->id, s->fd);
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
        }
  
        return WORK_OK;
}

enum work_status client_connect_result(struct client *c)
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

void socket_close(struct socket *s)
{
        LOG_DBG("c=%u closing socket %d\n", s->c->id, s->fd);
        s->state = SS_CLOSED;
        close(s->fd);
}

enum work_status client_close(struct client *c)
{
        LOG_DBG("client %u exits, "
                "serval=%zu/%zu inet=%zu/%zu\n", 
                c->id, 
                c->sock[ST_SERVAL].bytes_read, 
                c->sock[ST_SERVAL].bytes_written,
                c->sock[ST_INET].bytes_read, 
                c->sock[ST_INET].bytes_written);
        
        if (c->sock[ST_INET].bytes_in_pipe > 0) {
                LOG_ERR("warning: INET socket fd=%d still has "
                        "%zu bytes in pipe\n",
                        c->sock[ST_INET].fd, 
                        c->sock[ST_INET].bytes_in_pipe);
        }
        
        if (c->sock[ST_SERVAL].bytes_in_pipe > 0) {
                LOG_ERR("warning: SERVAL socket fd=%d still has "
                        "%zu bytes in pipe\n",
                        c->sock[ST_SERVAL].fd, 
                        c->sock[ST_SERVAL].bytes_in_pipe);
        }

        if (c->sock[ST_INET].state != SS_CLOSED)
                socket_close(&c->sock[ST_INET]);
        
        if (c->sock[ST_SERVAL].state != SS_CLOSED)
                socket_close(&c->sock[ST_SERVAL]);

        close(c->sock[ST_INET].splicefd[0]);
        close(c->sock[ST_INET].splicefd[1]);
        close(c->sock[ST_SERVAL].splicefd[0]);
        close(c->sock[ST_SERVAL].splicefd[1]);
        
        return WORK_EXIT;
}
