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
#define ENABLE_DEBUG 1
#include <common/debug.h>
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
} sockaddr_generic_t;

struct socket {
        int fd;
        unsigned char should_close:1;
        size_t bytes_written, bytes_read;
        socklen_t sndbuf;
};

enum sockettype {
        ST_INET,
        ST_SERVAL,
};

struct client {
        int from_family;
        unsigned int id;
        sockaddr_generic_t addr;
        socklen_t addrlen;
        pthread_t thr;
        struct socket sock[2];
        int translator_port;
        int splicefd[2];
        unsigned char is_garbage;
        struct list_head lh;
        struct signal exit_signal;
};

struct translator_init_pkt {
        struct in_addr addr;
        uint16_t port;
} __attribute__((packed));

#define DEFAULT_TRANSLATOR_PORT 8080
static LOG_DEFINE(logh);
struct signal exit_signal;
static LIST_HEAD(client_list);
int cross_translate = 0;

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

enum work_status {
        WORK_OK,
        WORK_CLOSED,
        WORK_NOSPACE,
        WORK_ERROR,
};

static enum work_status work_translate(struct socket *from, 
                                       struct socket *to,
                                       int splicefd[2])
{
        ssize_t ret;
        size_t readlen, nbytes;
        enum work_status status = WORK_OK;
        int bytes_queued = 0;
        
        ret = ioctl(to->fd, TIOCOUTQ, &bytes_queued);

        if (ret == -1) {
                LOG_ERR("ioctl error - %s\n", strerror(errno));
                return WORK_ERROR;
        }

        readlen = from->sndbuf - bytes_queued;
        
        if (readlen == 0)
                return WORK_NOSPACE;

        /* LOG_DBG("reading %zu bytes\n", readlen); */

        ret = splice(from->fd, NULL, splicefd[1], NULL, 
                     readlen, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        
        if (ret == -1) {
                LOG_ERR("splice1: %s\n",
                        strerror(errno));
                if (errno == EWOULDBLOCK)
                        return WORK_OK;
                return WORK_ERROR;
        } else if (ret == 0) {
                LOG_DBG("splice1: other end closed\n");
                from->should_close = 1;
                return WORK_OK;
        }       
        
        readlen = ret;
        from->bytes_read += readlen;

        /* LOG_DBG("splice1 %zu bytes\n", readlen); */

        while (readlen) {
                ret = splice(splicefd[0], NULL, to->fd, NULL,
                             readlen, SPLICE_F_MOVE);
                
                if (ret == -1) {
                        if (errno == EPIPE) {
                                LOG_DBG("splice2: EPIPE\n");
                                status = WORK_ERROR;
                        } else if (errno == EWOULDBLOCK) {
                        } else {
                                LOG_ERR("splice2: %s\n",
                                        strerror(errno));
                                status = WORK_ERROR;
                        }
                        break;
                } else if (ret > 0) {
                        to->bytes_written += ret;
                        nbytes += ret;
                        readlen -= ret;
                }
        }
        
        /* LOG_DBG("splice2 %zu bytes\n", nbytes); */
        
        return status;
}

static enum work_status work_inet_to_serval(struct client *c)
{
        return work_translate(&c->sock[ST_INET], &c->sock[ST_SERVAL], c->splicefd);
}

static enum work_status work_serval_to_inet(struct client *c)
{
        return work_translate(&c->sock[ST_SERVAL], &c->sock[ST_INET], c->splicefd);
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
        INIT_LIST_HEAD(&c->lh);
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
                memcpy(&c->addr, sa, salen);

                c->sock[ST_SERVAL].fd = socket(AF_SERVAL, SOCK_STREAM, 0);
                
                if (c->sock[ST_SERVAL].fd == -1) {
                        LOG_ERR("serval socket: %s\n",
                                strerror(errno));
                        goto fail_sock;
                }
        } else if (c->from_family == AF_SERVAL) {
                /* We're translating from AF_SERVAL to AF_INET */
                c->sock[ST_SERVAL].fd = sock;
                memcpy(&c->addr, sa, salen);
                
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
        }

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

static int client_send_init_packet(struct client *c)
{
        struct translator_init_pkt tip;
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);
        size_t tot_sent = 0, send_len = sizeof(tip);
        unsigned char *send_ptr = (unsigned char *)&tip;
        int ret;

        ret = getsockopt(c->sock[ST_INET].fd, SOL_IP, SO_ORIGINAL_DST, 
                         &addr, &addrlen);
        
        if (ret == -1) {
                LOG_DBG("client %u, could not get original port."
                        "Probably not NAT'ed\n", c->id);
                return -1;
        } else {
                char buf[18];
                
                inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf));

                LOG_DBG("Original dst: %s:%u\n",
                        buf, ntohs(addr.sin_port));
        }

        /* Send destination addr and port to other end */        
        memset(&tip, 0, sizeof(tip));
        memcpy(&tip.addr, &addr.sin_addr, sizeof(tip.addr));
        tip.port = addr.sin_port;
        
        do {
                ret = send(c->sock[ST_SERVAL].fd, send_ptr, send_len, 0);
                
                if (ret == 0) {
                        LOG_DBG("client %u other proxy closed\n",
                                c->id);
                } else if (ret == -1) {
                        LOG_ERR("client %u init packet: %s\n", 
                                c->id, strerror(errno));
                } else {
                        tot_sent += ret;
                        send_len -= ret;
                        send_ptr += ret;
                }
        } while (send_len > 0 && ret > 0);

        LOG_DBG("client %u sent %zu bytes init pkt\n",
                c->id, tot_sent);

        return ret;
}

static void *client_thread(void *arg)
{
        struct client *c = (struct client *)arg;
        sockaddr_generic_t addr;
        socklen_t addrlen;
        int sock = -1;
        char ipstr[18];
        int running = 1, ret;
        int should_send_init_pkt = 0;

        memset(&addr, 0, sizeof(addr));
        
        if (c->from_family == AF_SERVAL) {
                struct translator_init_pkt tip;
                
                if (!cross_translate) {
                        LOG_ERR("AF_SERVAL to AF_INET without cross-translation enabled\n");
                        goto done;
                }
                /* Receive destination addr and port from other end */
                ret = recv(c->sock[ST_SERVAL].fd, &tip, sizeof(tip), MSG_WAITALL);

                if (ret == -1) {
                        LOG_ERR("client %u could not read init packet: %s\n",
                                c->id, strerror(errno));
                        goto done;
                } else if (ret != sizeof(tip)) {
                        LOG_ERR("client %u bad init packet size %d\n",
                                c->id, ret);
                        goto done;
                }
                
                LOG_DBG("client %u received %d bytes init pkt\n",
                        c->id, ret);

                addr.in.sin_family = AF_INET;
                memcpy(&addr.in.sin_addr, &tip.addr, sizeof(tip.addr));
                addr.in.sin_port = tip.port;
                addrlen = sizeof(addr.in);
                sock = c->sock[ST_INET].fd;

                inet_ntop(AF_INET, &addr.in.sin_addr, 
                          ipstr, sizeof(ipstr));
                
                LOG_DBG("client %u connecting to %s:%u\n",
                        c->id, ipstr, ntohs(addr.in.sin_port));
        } else if (c->from_family == AF_INET) {
                addr.sv.sv_family = AF_SERVAL;
                addr.sv.sv_srvid.s_sid32[0] = htonl(c->translator_port);
                addrlen = sizeof(addr.sv);
                sock = c->sock[ST_SERVAL].fd;
                if (cross_translate)
                        should_send_init_pkt = 1;
                inet_ntop(AF_INET, &c->addr.in.sin_addr, ipstr, 18);

                LOG_DBG("client %u from %s connecting to service %s...\n",
                        c->id, ipstr, service_id_to_str(&addr.sv.sv_srvid));
        } else {
                LOG_ERR("client %u - bad address family, exiting\n",
                        c->id);
                goto done;
         }
       
        ret = connect(sock, &addr.sa, addrlen);

        if (ret == -1) {
                LOG_ERR("connect failed: %s\n",
                        strerror(errno));
                goto done;
        }
        
        LOG_DBG("client %u connected successfully!\n", c->id);

        while (running) {
                struct pollfd fds[3];
                enum work_status status;

                memset(fds, 0, sizeof(fds));
                fds[0].fd = signal_get_fd(&c->exit_signal);
                fds[0].events = POLLIN | POLLERR | POLLHUP;
                fds[1].fd = c->sock[ST_INET].fd;
                fds[1].events = POLLIN | POLLERR;
                fds[2].fd = c->sock[ST_SERVAL].fd;
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
                        if (should_send_init_pkt == 1) {
                                ret = client_send_init_packet(c);

                                if (ret <= 0) {
                                        LOG_ERR("client %u could not send init packet, ret=%d\n", c->id, ret);
                                        running = 0;
                                        break;
                                }
                                should_send_init_pkt = 0;
                        }
                        
                        status = work_inet_to_serval(c);
                        
                        if (status == WORK_ERROR) {
                                LOG_ERR("forwarding error\n");
                                running = 0;
                        } 
                }

                if (fds[2].revents & POLLERR) {
                        running = 0;
                } else if (fds[2].revents) {
                        status = work_serval_to_inet(c);
                        
                        if (status == WORK_ERROR) {
                                LOG_ERR("forwarding error\n");
                                running = 0;
                        }
                }

                if (c->sock[0].should_close ||
                    c->sock[1].should_close) 
                        running = 0;
        }
 done:
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

        return NULL;
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

                if (!c->is_garbage) {
                        signal_raise(&c->exit_signal);
                        /* Sending an interrupt signal in case the
                           thread is stuck on, e.g., a connect() */
                        pthread_kill(c->thr, SIGINT);
                }
                list_del(&c->lh);
                LOG_DBG("cleaning up client %u\n", c->id);
                pthread_join(c->thr, NULL);
                client_free(c);
        }
}

static int create_server_sock(int family, unsigned short port)
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
                addr.sv.sv_srvid.s_sid32[0] = htonl(port);
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

static int accept_client(int sock, int port)
{
        sockaddr_generic_t addr;
        socklen_t addrlen = sizeof(addr);
        int ret, client_sock;
        struct client *c;

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
                return -1;
        }

        LOG_DBG("accepted %s client\n", 
                family_to_str(addr.sa.sa_family));

        c = client_create(client_sock, &addr.sa, addrlen);        
        if (!c) {
                LOG_ERR("Could not create client, family=%d\n", 
                        addr.sa.sa_family);
                goto err;
        }

        c->translator_port = port;
        
        ret = pthread_create(&c->thr, NULL, client_thread, c);
        
        if (ret != 0) {
                LOG_ERR("pthread_create: %s\n",
                        strerror(errno));
                client_free(c);
                goto err;
        }
        
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
        
        return ret;       
 err:
        close(client_sock);
        return -1;
}

int run_translator(int family, unsigned short port)
{
	struct sigaction action;
	int sock, ret = 0, running = 1;

        memset(&action, 0, sizeof(struct sigaction));
        action.sa_handler = signal_handler;
        
	/* The server should shut down on these signals. */
        sigaction(SIGTERM, &action, 0);
	sigaction(SIGHUP, &action, 0);
	sigaction(SIGINT, &action, 0);
        sigaction(SIGPIPE, &action, 0);
        
        signal_init(&exit_signal);

        sock = create_server_sock(family, port);

        if (sock == -1) {
                LOG_ERR("could not create AF_INET server sock\n");
                signal_destroy(&exit_signal);
                return -1;
        }

        LOG_DBG("%s to %s translator running on port/serviceID %u\n", 
                family_to_str(family), 
                family_to_str(family == AF_INET ? AF_SERVAL : AF_INET),
                port);

        while (running) {
                struct pollfd fds[2];

                memset(fds, 0, sizeof(fds));
                fds[0].fd = signal_get_fd(&exit_signal);
                fds[0].events = POLLIN | POLLERR | POLLHUP;
                fds[0].revents = 0;
                fds[1].fd = sock;
                fds[1].events = POLLIN | POLLERR | POLLHUP;
                fds[1].revents = 0;

                ret = poll(fds, 2, 10000);
                
                if (ret == -1) {
                        /* Treat this as fatal error */
                        running = 0;
                        continue;
                } else if (ret == 0) {
                        /* Garbage collect */
                        /* LOG_DBG("garbage collecting clients\n"); */
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
                        LOG_DBG("accepting client\n");
                        ret = accept_client(sock, port); 
                        
                        if (ret == -1) {
                                LOG_ERR("could not accept new client\n");
                        }
                }
        }
        
        LOG_DBG("Translator exits.\n");
        cleanup_clients();
	close(sock);
        signal_destroy(&exit_signal);

        return ret;
}

#if !defined(OS_ANDROID)

static void print_usage(void)
{
        printf("Usage: translator [ OPTIONS ]\n");
        printf("where OPTIONS:\n");
        printf("\t-d, --daemon\t\t run in the background as a daemon.\n");
        printf("\t-p, --port PORT\t\t port to listen on.\n");
        printf("\t-l, --log LOG_FILE\t\t file to write client IPs to.\n");
        printf("\t-s, --serval\t\t run an AF_SERVAL to AF_INET translator.\n");
        printf("\t-x, --x-translate\t\t cross translate, i.e., this translator will connect to another translator that reverses the translation.\n");
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
                           strcmp(argv[0], "--x-translate") ==  0) {
                        cross_translate = 1;
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

        ret = run_translator(family, port);
fail:
        if (log_is_open(&logh))
                log_close(&logh);

	return ret;
}

#endif /* OS_ANDROID */
