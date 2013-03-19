/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- 
 *
 * The Serval stack as a user-space daemon. This implements the main
 * runloop and interactions with clients (i.e., apps that interact
 * with the stack).
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#include <stdlib.h>
#include <sys/types.h>  
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/select.h>
#include <poll.h>
#include <errno.h>
#include <libgen.h>
#include <serval/platform.h>
#include <serval/debug.h>
#include <serval/atomic.h>
#include <serval/list.h>
#include <serval/netdevice.h>
#include <serval/timer.h>
#include <af_serval.h>
#include <userlevel/client.h>
#include <ctrl.h>

struct client_list client_list;
atomic_t num_clients = ATOMIC_INIT(0);
static volatile int should_exit = 0;
static char *progname = NULL;

extern int telnet_init(void);
extern void telnet_fini(void);
unsigned int checksum_mode = 1;

#define MAX(x, y) (x >= y ? x : y)

void signal_handler(int sig)
{
        /* printf("signal caught! exiting...\n"); */
        should_exit = 1;       
}

#define GARBAGE_INTERVAL (jiffies + secs_to_jiffies(10))
static void garbage_collect_clients(unsigned long data);
static DEFINE_TIMER(garbage_timer, garbage_collect_clients, 0, 0);

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
	if ((chdir("/")) < 0) {
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

void garbage_collect_clients(unsigned long data)
{
	int num = 0;
	struct list_head *pos, *tmp;

        client_list_lock(&client_list);

	list_for_each_safe(pos, tmp, &client_list.head) {
		struct client *c = __client_list_entry(pos);
		
		if (client_get_state(c) == CLIENT_STATE_GARBAGE) {
			LOG_INF("Garbage collecting client %u\n", client_get_id(c));
			
			if (pthread_join(client_get_thread(c), NULL) != 0) {
				if (errno == EINVAL) {
					LOG_DBG("Client %u probably detached\n", 
						client_get_id(c));
				} else {
					LOG_ERR("Client %u could not be joined\n", 
						client_get_id(c));
				}
			}
                        __client_list_del(c);
			client_put(c);
			num++;
		}
	}
        client_list_unlock(&client_list);

	/* Schedule us again */
	mod_timer(&garbage_timer, GARBAGE_INTERVAL);
}

#define NUM_SERVER_SOCKS 2

#if defined(OS_ANDROID)
#define UDP_SERVER_PATH "/data/local/tmp/serval-udp.sock"
#define TCP_SERVER_PATH "/data/local/tmp/serval-tcp.sock"
#else
#define UDP_SERVER_PATH "/tmp/serval-udp.sock"
#define TCP_SERVER_PATH "/tmp/serval-tcp.sock"
#endif 

static char *server_sock_path[] = {
	UDP_SERVER_PATH,
	TCP_SERVER_PATH
};

static int server_run(void)
{	
	sigset_t sigset, orig_sigset;
	int server_sock[NUM_SERVER_SOCKS], i, ret = 0;
	struct sockaddr_un sa;
        int timer_list_signal[2];
        
        /* pipe/signal to tell us when a new timer timeout must be
         * scheduled */
        ret = pipe(timer_list_signal);
        
        if (ret == -1) {
                LOG_ERR("could not open signal pipe: %s\n",
                        strerror(errno));
                return -1;
        }
        
	sigemptyset(&sigset);
        sigaddset(&sigset, SIGTERM);
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGINT);
        
        /* Block the signals we are watching here so that we can
         * handle them in pselect instead. */
        sigprocmask(SIG_BLOCK, &sigset, &orig_sigset);
	
	if (should_exit) {
                goto out_close_pipe;
        }
        
	for (i = 0; i < NUM_SERVER_SOCKS; i++) {
		server_sock[i] = socket(AF_UNIX, SOCK_STREAM, 0);

		if (server_sock[i] == -1) {
			LOG_ERR("Failure. AF_UNIX server socket %s : %s\n", 
				server_sock_path[i], strerror(errno));
			ret = -1;
                        goto out_close_pipe;
		}

		memset(&sa, 0, sizeof(sa));
		sa.sun_family = AF_UNIX;
		strcpy(sa.sun_path, server_sock_path[i]);
	
		ret = bind(server_sock[i], (struct sockaddr *)&sa, sizeof(sa));

		if (ret == -1) {
			LOG_ERR("bind failed for AF_UNIX socket %s : %s\n",
				server_sock_path[i], strerror(errno));
			goto out_close_socks;
		}

		ret = chmod(server_sock_path[i], S_IRWXU|S_IRWXG|S_IRWXO);

		if (ret == -1) {
			LOG_ERR("chmod file %s : %s\n",
				server_sock_path[i], strerror(errno));
			goto out_close_socks;
		}

		ret = listen(server_sock[i], 10);

		if (ret == -1) {
                        LOG_ERR("listen failed for AF_UNIX socket %s : %s\n",
				server_sock_path[i], strerror(errno));
			goto out_close_socks;
		}
	}

	LOG_DBG("Server starting\n");
	/* Add garbage collection timer */
	mod_timer(&garbage_timer, GARBAGE_INTERVAL);

	while (!should_exit) {
		fd_set readfds;
		struct timespec *to = NULL, timeout = { 0, 0 };
		int maxfd = -1;

		FD_ZERO(&readfds);

		for (i = 0; i < NUM_SERVER_SOCKS; i++) {
			FD_SET(server_sock[i], &readfds);
			maxfd = MAX(maxfd, server_sock[i]);
		}

		FD_SET(ctrl_getfd(), &readfds);
		maxfd = MAX(maxfd, ctrl_getfd());

		FD_SET(timer_list_signal[0], &readfds);
		maxfd = MAX(maxfd, timer_list_signal[0]);

		ret = timer_list_get_next_timeout(&timeout, 
                                                  timer_list_signal);

                if (timeout.tv_sec < 0)
                        goto handle_timeout;

		if (ret == -1) {
			/* Timer list error. Exit? */
			break;
		} else if (ret == 0) {
			/* No timer */
			to = NULL;
		} else {
			to = &timeout;
		}
#if defined(HAVE_PSELECT)
		ret = pselect(maxfd + 1, &readfds, 
			      NULL, NULL, to, &orig_sigset);		
#else
		{
			/* Emulate pselect behavior. Potential
                           problem: these calls are not atomic. */
			struct timeval tv, *t = NULL;
			sigset_t old_set;

			if (to) {
				tv.tv_sec = to->tv_sec;
				tv.tv_usec = to->tv_nsec / 1000;
				t = &tv;
			}

			sigprocmask(SIG_SETMASK, &orig_sigset, &old_set);
			
			if (should_exit) {
				sigprocmask(SIG_SETMASK, &old_set, NULL);
				break;
			}
				
			ret = select(maxfd + 1, &readfds, NULL, NULL, t);

			sigprocmask(SIG_SETMASK, &old_set, NULL);
		}
#endif
		if (ret == -1) {
			if (errno == EINTR) {
				LOG_INF("select interrupted\n");
				continue;
			} else if (errno == EINVAL) {
                                LOG_ERR("Invalid timeout or negative ndfs\n");
                                LOG_ERR("Timeout is %ld %ld\n", 
                                        to->tv_sec, to->tv_nsec);
                        }
                       
			LOG_ERR("select : %s\n", 
                                strerror(errno));
                        LOG_ERR("Exiting due to error!!!\n");
			break;                                        
		} else if (ret == 0) {
                handle_timeout:
			/* Timeout, handle timers */
			timer_list_handle_timeout();
			continue;
		}
		
                if (FD_ISSET(timer_list_signal[0], &readfds)) {
                        timer_list_signal_lower();
                }
		if (FD_ISSET(ctrl_getfd(), &readfds)) {
			ret = ctrl_recvmsg();

			if (ret == -1) {
				LOG_ERR("ctrlmsg recv error\n");
			}
		}
		
		for (i = 0; i < NUM_SERVER_SOCKS; i++) {
			if (FD_ISSET(server_sock[i], &readfds)) {
				int client_sock;
				socklen_t addrlen = 0;
				struct client *c;

				LOG_INF("client event\n");
				
				client_sock = accept(server_sock[i], 
						     (struct sockaddr *)&sa, 
                                                     &addrlen);
				
				if (client_sock == -1) {
					LOG_ERR("accept() failed : %s\n", 
						strerror(errno));
					continue;
				} 
					
				/* TODO: should use something
				 * more explicit for the
				 * client type than the
				 * 'i' variable */
				c = client_create(i, client_sock, 
                                                  atomic_inc_return(&num_clients), 
						  &sa, &orig_sigset);
				
				if (!c) {
					close(client_sock);
				} else {
					LOG_INF("accepted new client %u\n", 
                                                client_get_id(c));
					
					client_list_add(c, &client_list);
					
					ret = client_start(c);
					
					if (ret == -1) {
						LOG_ERR("Could not start client\n");
                                                __client_list_del(c);
						client_put(c);
					}
				}
			}
		}
	}
	
        client_list_lock(&client_list);

	while (!list_empty(&client_list.head)) {
		struct client *c = __client_list_first_entry(&client_list);

		LOG_INF("Joining with client %u\n", client_get_id(c));
		client_signal_exit(c);

		if (pthread_join(client_get_thread(c), NULL) != 0) {
			if (errno == EINVAL) {
				LOG_DBG("Client %u probably detached\n", 
					client_get_id(c));
			} else {
				LOG_ERR("Client %u could not be joined\n", 
					client_get_id(c));
			}
		}
                __client_list_del(c);
		client_put(c);
	}
        client_list_unlock(&client_list);

out_close_socks:
	for (i = 0; i < NUM_SERVER_SOCKS; i++) {
		close(server_sock[i]);
		unlink(server_sock_path[i]);
	}
out_close_pipe:
        close(timer_list_signal[0]);
        close(timer_list_signal[1]);
	return ret;
}

extern void dev_list_add(const char *name);

#define PID_FILE "/tmp/serval.pid"

static int write_pid_file(void)
{
        FILE *f;

        f = fopen(PID_FILE, "w");
        
        if (!f) {
                fprintf(stderr, "Could not write PID file to %s : %s\n",
                        PID_FILE, strerror(errno));
                return -1;
        }

        fprintf(f, "%u\n", getpid());

        fclose(f);

        return 0;
}

#define BUFLEN 256

enum {
        SERVAL_NOT_RUNNING = 0,
        SERVAL_RUNNING,
        SERVAL_BAD_PID,
        SERVAL_CRASHED,
};

static int check_pid_file(void)
{
        FILE *f;
        pid_t pid;
        int res = SERVAL_NOT_RUNNING;

        f = fopen(PID_FILE, "r");
        
        if (!f) {
                switch (errno) {
                case ENOENT:
                        /* File probably doesn't exist */
                        return SERVAL_NOT_RUNNING;
                case EACCES:
                case EPERM:
                        /* Probably not owner and lack permissions */
                        return SERVAL_RUNNING;
                case EISDIR:
                default:
                        fprintf(stderr, "Pid file error: %s\n",
                                strerror(errno));
                }
                return SERVAL_BAD_PID;
        }
        
        if (fscanf(f, "%u", (unsigned *)&pid) == 0) {
                fprintf(stderr, "Could not read PID file %s\n",
                        PID_FILE);
                return SERVAL_BAD_PID;
        }
        
        LOG_DBG("Pid is %u\n", pid);

        fclose(f);

#if defined(OS_LINUX)
        {
                char buf[BUFLEN];
                snprintf(buf, BUFLEN, "/proc/%d/cmdline", pid);
                
                res = SERVAL_CRASHED;
                
                f = fopen(buf, "r");

                if (f) {
                        size_t nitems = fread(buf, 1, BUFLEN, f);
                        if (nitems && strstr(buf, progname) != NULL) 
                        res = SERVAL_RUNNING;
                        fclose(f);
                }
        }
#endif
        return res;
}

extern atomic_t num_skb_alloc;
extern atomic_t num_skb_free;
extern atomic_t num_skb_clone;

static void print_usage()
{
        printf("Usage: %s [OPTIONS]\n", progname);
        printf("-h, --help                        - Print this information.\n"
               "-i, --interface IFACE             - Use only the specified interface.\n"
               "-u, --udp-encap                   - Enable UDP encapsulation.\n"
               "-d, --daemon                      - Run in the background as a daemon.\n"
               "-l, --debug-level LEVEL           - Set the level of debug output.\n"
               "-s, --sal-forward                 - Enable SAL forwarding.\n");
}

int main(int argc, char **argv)
{        
	struct sigaction action;
        int daemon = 0;
	int ret;
        struct timeval now;
        
        progname = basename(argv[0]);

        ret = check_pid_file();

        if (ret == SERVAL_RUNNING) {
                LOG_CRIT("A Serval instance is already running!\n");
                return -1;
        } else if (ret == SERVAL_CRASHED) {
                LOG_DBG("A previous Serval instance seems to have crashed!\n");
                unlink(PID_FILE);

                /* Cleanup old stuff from crashed instance */
                unlink(SERVAL_STACK_CTRL_PATH);
                unlink(TCP_SERVER_PATH);
                unlink(UDP_SERVER_PATH);
        }

	if (getuid() != 0 && geteuid() != 0) {
		fprintf(stderr, "%s must run as uid=0 (root)\n", progname);
                return -1;
	}

        if (write_pid_file() != 0) {
                LOG_CRIT("Could not write PID file!\n");
                return -1;
        }

	memset(&action, 0, sizeof(struct sigaction));
        action.sa_handler = signal_handler;
        
	/* The server should shut down on these signals. */
        sigaction(SIGTERM, &action, 0);
        sigaction(SIGHUP, &action, 0);
	sigaction(SIGINT, &action, 0);
	
        client_list_init(&client_list);
        
        /* Seed random number generator */
        gettimeofday(&now, NULL);
        
        srandom((unsigned int)now.tv_usec);
                
	argc--;
	argv++;
        
	while (argc) {
                if (strcmp(argv[0], "-i") == 0 ||
		    strcmp(argv[0], "--interface") == 0) {
			dev_list_add(argv[1]);
			argv++;
			argc--;
		} else if (strcmp(argv[0], "-ipf") == 0 ||
                           strcmp(argv[0], "--ip-forward") == 0) {
                        /* How do we set this? */
                } else if (strcmp(argv[0], "-h") == 0 ||
                           strcmp(argv[0], "--help") == 0) {
                        print_usage();
                        return -1;
                } else if (strcmp(argv[0], "-s") == 0 ||
                           strcmp(argv[0], "--sal-forward") == 0) {
                        LOG_DBG("Enabling SAL forwarding\n");
                        net_serval.sysctl_sal_forward = 1;
                } else if (strcmp(argv[0], "-u") == 0 ||
                           strcmp(argv[0], "--udp-encap") == 0) {
                        net_serval.sysctl_udp_encap = 1;
                } else if (strcmp(argv[0], "-d") == 0 ||
                           strcmp(argv[0], "--daemon") == 0) {
                        daemon = 1;
                } else if (strcmp(argv[0], "-dl") == 0 ||
                           strcmp(argv[0], "-l") == 0 ||
                           strcmp(argv[0], "--debug-level") == 0) {
                        char *p = NULL;
                        unsigned int d = strtoul(argv[1], &p, 10);
                        
                        if (*argv[1] != '\0' && *p == '\0') {
                                argv++;
                                argc--;
                                LOG_INF("Setting debug to %u\n", d);
                                net_serval.sysctl_debug = d;
                        } else {
                                fprintf(stderr, "Invalid debug setting %s\n",
                                        argv[1]);
                                print_usage();
                                return -1;
                        }
                } else {
                        print_usage();
                        return -1;
                }
		argc--;
		argv++;
	}	
        
        if (daemon) {
                ret = daemonize();
                
                if (ret < 0) {
                        LOG_CRIT("Could not make daemon\n");
                        return -1;
                }
        }

	ret = serval_init();

	if (ret == -1) {
		LOG_CRIT("Could not initialize af_serval\n");   
                goto cleanup_pid;
	}
	
	ret = ctrl_init();
	
	if (ret == -1) {
		LOG_CRIT("Could not initialize ctrl socket.\n");
		LOG_CRIT("Check if %s already exists.\n", 
                         SERVAL_STACK_CTRL_PATH);   
                goto cleanup_serval;
	}
	
        ret = telnet_init();

        if (ret == -1) {
		LOG_CRIT("Could not initialize telnet server\n");
                goto cleanup_ctrl;
	}

	ret = server_run();

        telnet_fini();

 cleanup_ctrl:
	ctrl_fini();
 cleanup_serval:
	serval_fini();
 cleanup_pid:
        unlink(PID_FILE);

        LOG_DBG("num_skb_alloc=%u\n", atomic_read(&num_skb_alloc));
        LOG_DBG("num_skb_clone=%u\n", atomic_read(&num_skb_clone));
        LOG_DBG("num_skb_free=%u\n", atomic_read(&num_skb_free));

	return ret;
}
