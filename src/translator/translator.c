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
#include <pthread.h>
#include <signal.h>
#include <netdb.h>
#include <common/signal.h>
#include <common/list.h>
#include <common/timer.h>
#include <common/debug.h>
#include <common/log.h>
#include <sys/epoll.h>
#include "translator.h"
#include "client.h"
#include "worker.h"
/* 
   High-level overview of translator
   =================================

   The translator moves data between two sockets (AF_INET and
   AF_SERVAL) using the splice system call. With this call, the data
   never leaves kernel space, and the operation is therefore
   very efficient. The translator can accept connections on both types
   of sockets simultaneously and then automatically create a socket of
   the other type, connecting to the final server destination.

   The splice call requires connecting the two sockets via pipes,
   leaving us with a configuration as follows (when translating from
   AF_INET to AF_SERVAL):

   fd_inet ---> fd_pipe_w PIPE fd_pipe_r ---> fd_serval

   All in all, this leaves us with four file descriptors per client.

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

   The main thread is responsible for initially launching workers and
   to accept new clients on "listening" sockets. The new clients are
   assigned to workers based on how many clients each worker already
   have assigned (trying to maintain a uniform spread across
   workers). A worker takes complete responsiblity for its clients
   once assigned. The worker monitors its clients' file descriptors
   using its own epoll runloop, executing work in response to file
   descriptor events.
 */
#define DEFAULT_TRANSLATOR_PORT 8080
#define DEFAULT_SERVICE_ID "0x0000005"
static LOG_DEFINE(logh);
struct signal main_signal;

#define MAX_EVENTS 10
#define MAX_WORKERS 20

static struct worker *workers;
static unsigned int num_workers = 4;
enum debug_level debuglevel = DBG_LVL_NONE;

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

static void assign_client_to_worker(struct client *c)
{
        unsigned i, c_num = 0, min = workers[0].num_clients;

        LOG_DBG("client %u num_workes=%u\n", c->id, num_workers);
        
        /* FIXME: could use priority queue (min heap) here */
        for (i = 0; i < num_workers; i++) {
                if (workers[i].num_clients < min) {
                        c_num = i;
                        min = workers[i].num_clients;
                }
        }
        LOG_DBG("client %u assigned to worker %u\n",
                c->id, workers[c_num].id);
        
        worker_add_client(&workers[c_num], c);
}

static void signal_handler(int sig)
{
        LOG_DBG("signal %u caught!\n", sig);

        if (sig == SIGKILL || sig == SIGTERM)
                signal_raise_val(&main_signal, SIGNAL_EXIT);
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
#if defined(ENABLE_DEBUG)
                inet_ntop(AF_INET, &addr.sv_in.in.sin_addr, ip, 18);
#endif
                /* Only make serviceID visible */
                addrlen = sizeof(addr.sv);
        } else {
#if defined(ENABLE_DEBUG)
                inet_ntop(AF_INET, &addr.in.sin_addr, ip, 18);
#endif
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
        
        /* Make a note in our client log */
        if (addr.sa.sa_family == AF_INET && log_is_open(&logh)) {
                struct hostent *h;
                char buf[18];
                
                /* Cast to const char * to quell compiler on Android */
                h = gethostbyaddr((const char *)&addr.in.sin_addr, 4, AF_INET);
                
                log_printf(&logh, "c %s %s",
                           inet_ntop(AF_INET, &addr.in.sin_addr, 
                                     buf, sizeof(buf)),
                           h ? h->h_name : "unknown hostname");
        }
        
        return c;       
 err:
        close(client_sock);
        return NULL;
}

static int start_workers(unsigned int num)
{
        unsigned int i;
        
        LOG_DBG("Creating %u workers\n", num);

        workers = malloc(sizeof(struct worker) * num);
        
        if (!workers)
                return -1;        

        for (i = 0; i < num; i++) {
                struct worker *w = &workers[i];
                int ret;
                
                ret = worker_init(w, i);

                if (ret == -1) {
                        LOG_ERR("worker initialization failed\n");
                        return -1;
                }
                
                LOG_DBG("Starting worker %u\n", w->id);

                ret = worker_start(w);
                
                if (ret == -1) {
                        LOG_ERR("worker start failed!\n");
                        return -1;
                }
        }

        return 0;
}

static void stop_workers(void)
{
        unsigned int i;

        for (i = 0; i < num_workers; i++)
                signal_raise_val(&workers[i].sig, SIGNAL_EXIT);

        for (i = 0; i < num_workers; i++) {                
                LOG_DBG("joining with worker %u\n", i);
                pthread_join(workers[i].thr, NULL);
                worker_destroy(&workers[i]);
        }
        free(workers);
}

#define GC_TIMEOUT 3000

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
        int epollfd = -1;

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
                        //garbage_collect_clients();
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
                                        assign_client_to_worker(c);
                                }
                        } else if (s->fd == sig_fd) {
                                int val;

                                signal_clear_val(&main_signal, &val);
                                
                                switch (val) {
                                case SIGNAL_EXIT:
                                        running = 0;
                                        break;
                                default:
                                        break;
                                }
                        }
                }
        }
        LOG_DBG("Translator exits.\n");
err_workers:
        stop_workers();
        /* cleanup_clients(); */
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
                        argv++;
                        argc--;
                } else if (strcmp(argv[0], "-d") == 0 ||
                           strcmp(argv[0], "--daemon") ==  0) {
                        daemon = 1;
                } else if (strcmp(argv[0], "-x") == 0 ||
                           strcmp(argv[0], "--cross-translate") ==  0) {
                        cross_translate = 1;
                } else if (strcmp(argv[0], "-dl") == 0 ||
                           strcmp(argv[0], "--debug-level") ==  0) {
                        int level;
                        if (argc == 1) {
                                print_usage();
                                goto fail;
                        }
                        level = atoi(argv[1]);
                        if (level >= 0) {
                                if (level > DBG_LVL_MAX)
                                        level = DBG_LVL_MAX;
                                debuglevel = level;
                        }
                        argv++;
                        argc--;
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
                        argv++;
                        argc--;
                } else if (strcmp(argv[0], "-l") == 0 ||
                           strcmp(argv[0], "--log") ==  0) {
                        if (argc == 1 || log_is_open(&logh)) {
                                print_usage();
                                goto fail;
                        }
                        ret = log_open(&logh, argv[1], LOG_APPEND);

                        if (ret == -1) {
                                LOG_ERR("bad log file %s\n",
                                        argv[1]);
                                goto fail;
                        }

                        log_set_flag(&logh, LOG_F_TIMESTAMP);

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
