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
#include <common/signal.h>
#include <common/list.h>
#define ENABLE_DEBUG 1
#include <common/debug.h>
#include <poll.h>
#include <pthread.h>
#include "log.h"

#if defined(OS_ANDROID)
#include "splice.h"
#endif

static unsigned int client_num = 0;

struct client {
        int family;
        unsigned int id;
        struct sockaddr_in saddr;
        pthread_t thr;
        int inet_sock;
        int translator_port;
        int serval_sock;
        int splicefd[2];
        unsigned char is_garbage;
        struct list_head lh;
        struct signal exit_signal;
};

#define DEFAULT_TRANSLATOR_PORT 8080
static const char *server_ip = "192.168.56.101";
static LOG_DEFINE(logh);
struct signal exit_signal;
static LIST_HEAD(client_list);

static ssize_t forward_data(int from, int to, int splicefd[2])
{
        ssize_t rlen, wlen = 0;

         rlen = splice(from, NULL, splicefd[1], NULL, 
                       INT_MAX, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        
        if (rlen == -1) {
                LOG_ERR("splice1: %s\n",
                        strerror(errno));
                return rlen;
        } else if (rlen == 0) {
                LOG_DBG("Other end closed\n");
        }
        
        /* printf("splice1 %zd bytes\n", rlen); */
        
        while (rlen) {
                ssize_t w = splice(splicefd[0], NULL, to, NULL,
                                   rlen, SPLICE_F_MOVE | SPLICE_F_MORE);
                
                if (w == -1) {
                        LOG_ERR("splice2: %s\n",
                                strerror(errno));
                        break;
                }
                wlen += w;
                rlen -= w;
        }
        
        /* printf("splice2 %zd bytes\n", wlen); */
        
        return wlen;
}

static ssize_t legacy_to_serval(struct client *c)
{
        return forward_data(c->inet_sock, c->serval_sock, c->splicefd);
}

static ssize_t serval_to_legacy(struct client *c)
{
        return forward_data(c->serval_sock, c->inet_sock, c->splicefd);
}

struct client *client_create(int inet_sock, int family, 
                             struct sockaddr *sa, socklen_t salen)
{
        struct client *c;
        int ret;

        c = malloc(sizeof(struct client));

        if (!c)
                return NULL;
        
        memset(c, 0, sizeof(struct client));
        c->id = client_num++;
        c->inet_sock = inet_sock;
        c->family = family;
        c->is_garbage = 0;
        INIT_LIST_HEAD(&c->lh);
        signal_init(&c->exit_signal);
        
        ret = pipe(c->splicefd);

        if (ret == -1) {
                LOG_ERR("pipe: %s\n",
			strerror(errno));
                goto fail_pipe;
        }
        
        c->serval_sock = socket(family, SOCK_STREAM, 0);
        
	if (c->serval_sock == -1) {
		LOG_ERR("serval socket: %s\n",
			strerror(errno));
                goto fail_sock;
	}
        memcpy(&c->saddr, sa, salen);

        return c;
fail_sock:        
        close(c->splicefd[0]);
        close(c->splicefd[1]);
fail_pipe:
        free(c);
        signal_destroy(&c->exit_signal);
        return NULL;
}

static void client_free(struct client *c)
{
        signal_destroy(&c->exit_signal);
        free(c);
}

static void *client_thread(void *arg)
{
        struct client *c = (struct client *)arg;
        union {
                struct sockaddr sa;
                struct sockaddr_sv sv;
                struct sockaddr_in in;
        } addr;
        socklen_t addrlen;
        int inet_port = 49254;
        char srcstr[18];
        int running = 1, ret;

        memset(&addr, 0, sizeof(addr));
        
        if (c->family == AF_SERVAL) {
                addr.sv.sv_family = c->family;
                addr.sv.sv_srvid.s_sid32[0] = htonl(c->translator_port);
                addrlen = sizeof(addr.sv);
        } else {
                addr.in.sin_family = c->family;
                inet_pton(AF_INET, server_ip, &addr.in.sin_addr);
                addr.in.sin_port = htons(inet_port);
                addrlen = sizeof(addr.in);
        }
        
        inet_ntop(AF_INET, &c->saddr.sin_addr, 
                  srcstr, sizeof(srcstr));
        
        if (c->family == AF_SERVAL) {
                LOG_DBG("client %u from %s connecting to service %s...\n",
                        c->id, srcstr, service_id_to_str(&addr.sv.sv_srvid));
        } else {
                LOG_DBG("client %u from %s connecting to %s:%u...\n",
                        c->id, srcstr, server_ip, inet_port);
        }

        ret = connect(c->serval_sock, &addr.sa, addrlen);

        if (ret == -1) {
                LOG_ERR("connect failed: %s\n",
                        strerror(errno));
                client_free(c);
                return NULL;
        }

        LOG_DBG("client %u connected successfully!\n", c->id);

        while (running) {
                ssize_t bytes = 0;
                struct pollfd fds[3];

                memset(&fds, 0, sizeof(fds));
                fds[0].fd = signal_get_fd(&c->exit_signal);
                fds[0].events = POLLIN | POLLERR | POLLHUP;
                fds[1].fd = c->inet_sock;
                fds[1].events = POLLIN | POLLERR;
                fds[2].fd = c->serval_sock;
                fds[2].events = POLLIN | POLLERR;
                
                ret = poll(fds, 3, -1);

                if (ret == -1) {
                        LOG_ERR("poll: %s\n",
                                strerror(errno));
                        running = 0;
                        continue;
                }
                
                if (fds[0].revents) {
                        running = 0;
                        continue;
                } 

                if (fds[1].revents & POLLERR) {
                        running = 0;
                } else if (fds[1].revents) {
                        bytes = legacy_to_serval(c);
                        
                        if (bytes == 0) {
                                running = 0;
                        } else if (bytes < 0) {
                                LOG_ERR("forwarding error\n");
                                running = 0;
                        } 
                }

                if (fds[2].revents & POLLERR) {
                        running = 0;
                } else if (fds[2].revents) {
                        bytes = serval_to_legacy(c);
                        
                        if (bytes == 0) {
                                running = 0;
                        } else if (bytes < 0) {
                                LOG_ERR("forwarding error\n");
                                running = 0;
                        } 
                }                
        }

        LOG_DBG("client %u exits\n", c->id);
        c->is_garbage = 1;

        close(c->serval_sock);
        close(c->inet_sock);
        close(c->splicefd[0]);
        close(c->splicefd[1]);

        return NULL;
}

static void signal_handler(int sig)
{
        LOG_DBG("signal %u caught!\n", sig);
        signal_raise(&exit_signal);
}

static void print_usage(void)
{
        printf("Usage: translator [ OPTIONS ]\n");
        printf("where OPTIONS:\n");
        printf("\t-p, --port PORT\t\t port to listen on.\n");
        printf("\t-l, --log LOG_FILE\t\t file to write client IPs to.\n");
}

static void garbage_collect_clients(void)
{
        struct client *c, *tmp;

        list_for_each_entry_safe(c, tmp, &client_list, lh) {
                if (c->is_garbage) {
                        LOG_DBG("garbage collecting client %u\n", c->id);
                        list_del(&c->lh);
                        pthread_join(c->thr, NULL);
                        client_free(c);
                }
        }
}

static void cleanup_clients(void)
{
        while (!list_empty(&client_list)) {
                struct client *c;

                c = list_first_entry(&client_list, struct client, lh);

                if (!c->is_garbage)
                        signal_raise(&c->exit_signal);

                list_del(&c->lh);
                LOG_DBG("cleaning up client %u\n", c->id);
                pthread_join(c->thr, NULL);
                client_free(c);
        }
}

int run_translator(unsigned short port)
{
	struct sigaction action;
	int sock, ret = 0, running = 1;
	struct sockaddr_in saddr;
	int family = AF_SERVAL;

        memset(&action, 0, sizeof(struct sigaction));
        action.sa_handler = signal_handler;
        
	/* The server should shut down on these signals. */
        sigaction(SIGTERM, &action, 0);
	sigaction(SIGHUP, &action, 0);
	sigaction(SIGINT, &action, 0);
        sigaction(SIGPIPE, &action, 0);
        
        signal_init(&exit_signal);

	sock = socket(AF_INET, SOCK_STREAM, 0);

	if (sock == -1) {
		LOG_ERR("inet socket: %s\n",
			strerror(errno));
                goto fail_sock;
	}

        ret = 1;
        
        ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &ret, sizeof(ret));
        
        if (ret == -1) {
                LOG_ERR("Could not set SO_REUSEADDR - %s\n",
                        strerror(errno));
        }
        
        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = INADDR_ANY;
        saddr.sin_port = htons(port);

        LOG_DBG("Serval translator running on port %u\n", 
                port);

        ret = bind(sock, (struct sockaddr *)&saddr, sizeof(saddr));

        if (ret == -1) {
		LOG_ERR("inet bind: %s\n",
			strerror(errno));
                goto fail_bind_sock;
	}

        ret = listen(sock, 10);

        if (ret == -1) {
                LOG_ERR("inet listen: %s\n",
			strerror(errno));
                goto fail_bind_sock;
        }

        while (running) {
                int client_sock;
                socklen_t addrlen = sizeof(saddr);
                struct client *c;
                struct pollfd fds[2];

                LOG_DBG("Waiting for new clients...\n");

                memset(fds, 0, sizeof(fds));

                fds[0].fd = signal_get_fd(&exit_signal);
                fds[0].events = POLLIN | POLLERR | POLLHUP;
                fds[1].fd = sock;
                fds[1].events = POLLIN | POLLERR | POLLHUP;
                
                ret = poll(fds, 2, 10000);
                
                if (ret == -1) {
                        /* Treat this as fatal error */
                        running = 0;
                        continue;
                } else if (ret == 0) {
                        /* Garbage collect */
                        garbage_collect_clients();
                        continue;
                }
                
                if (fds[0].revents) {
                        running = 0;
                        continue;
                }
                
                if (fds[1].revents & POLLHUP ||
                    fds[1].revents & POLLERR) {
                        running = 0;
                        continue;
                }
                
                if (fds[1].revents & POLLIN) {
                        client_sock = accept(sock, (struct sockaddr *)&saddr,
                                             &addrlen);
                        
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
                                continue;
                        } 
                        
                        c = client_create(client_sock, family, 
                                          (struct sockaddr *)&saddr, addrlen);
                        
                        if (!c) {
                                LOG_ERR("Could not create client\n");
                                close(client_sock);
                                continue;
                        }
                        
                        c->translator_port = port;
                        
                        ret = pthread_create(&c->thr, NULL, client_thread, c);
                        
                        if (ret != 0) {
                                LOG_ERR("pthread_create: %s\n",
                                        strerror(errno));
                                client_free(c);
                                continue;
                        }
                        
                        list_add_tail(&c->lh, &client_list);

                        /* Make a note in our client log */
                        if (log_is_open(&logh)) {
                                struct hostent *h;
                                char buf[18];
                                
                                /* Cast to const char * to quell compiler on Android */
                                h = gethostbyaddr((const char *)&saddr.sin_addr, 4, AF_INET);
                                
                                log_write_line(&logh, "c %s %s",
                                               inet_ntop(AF_INET, &saddr.sin_addr, 
                                                         buf, sizeof(buf)),
                                               h ? h->h_name : "unknown hostname");
                        }
                }
        }
        
        LOG_DBG("Translator exits.\n");
        cleanup_clients();
fail_bind_sock:
	close(sock);
fail_sock:
        signal_destroy(&exit_signal);

        return ret;
}

#if !defined(OS_ANDROID)
int main(int argc, char **argv)
{       
        unsigned short port = DEFAULT_TRANSLATOR_PORT;
        int ret = 0;

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

        ret = run_translator(port);
fail:
        if (log_is_open(&logh))
                log_close(&logh);

	return ret;
}

#endif /* OS_ANDROID */
