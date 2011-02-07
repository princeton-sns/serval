/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <stdlib.h>
#include <sys/types.h>  
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
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

extern int telnet_init(void);
extern void telnet_fini(void);

#define MAX(x, y) (x >= y ? x : y)

void signal_handler(int sig)
{
        /* printf("signal caught! exiting...\n"); */
        should_exit = 1;       
}

static void garbage_collect_clients(unsigned long data);
static DEFINE_TIMER(garbage_timer, garbage_collect_clients, 10000000, 0);

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
	f = freopen("/dev/null", "w", stdout);
	f = freopen("/dev/null", "w", stderr);

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
	add_timer(&garbage_timer);
}

#define NUM_SERVER_SOCKS 2

#if defined(OS_ANDROID)
#define UDP_SERVER_PATH "/data/local/tmp/serval-udp.sock"
#define TCP_SERVER_PATH "/data/local/tmp/serval-tcp.sock"
#else
#define UDP_SERVER_PATH "/tmp/serval-udp.sock"
#define TCP_SERVER_PATH "/tmp/serval-tcp.sock"
#endif 

static const char *server_sock_path[] = {
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
	add_timer(&garbage_timer);

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
			/* Emulate pselect behavior */
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
			}
			LOG_ERR("select error...\n");
			break;                                        
		} else if (ret == 0) {
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
						     (struct sockaddr *)&sa, &addrlen);
				
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
					LOG_INF("accepted new client\n");
					
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

int main(int argc, char **argv)
{        
	struct sigaction action;
        int daemon = 0;
	int ret;
	
	if (getuid() != 0 && geteuid() != 0) {
		fprintf(stderr, "%s must run as uid=0 (root)\n",
			basename(argv[0]));
			return -1;
	}
	
	memset(&action, 0, sizeof(struct sigaction));
        action.sa_handler = signal_handler;
        
	/* The server should shut down on these signals. */
        sigaction(SIGTERM, &action, 0);
	sigaction(SIGHUP, &action, 0);
	sigaction(SIGINT, &action, 0);
	
        client_list_init(&client_list);

	argc--;
	argv++;
        
	while (argc) {
                if (strcmp(argv[0], "-i") == 0 ||
		    strcmp(argv[0], "--interface") == 0) {
			dev_list_add(argv[1]);
			argv++;
			argc--;
		} else if (strcmp(argv[0], "-d") == 0 ||
                           strcmp(argv[0], "--daemon") == 0) {
                        daemon = 1;
		}
		argc--;
		argv++;
	}	
      
        if (daemon) {
                ret = daemonize();

                if (ret < 0) {
                        LOG_ERR("Could not make daemon\n");
                        return -1;
                } 
        }

	ret = serval_init();

	if (ret == -1) {
		LOG_ERR("Could not initialize af_serval\n");
                netdev_fini();
		return -1;
	}
	
	ret = ctrl_init();
	
	if (ret == -1) {
		LOG_ERR("Could not initialize ctrl socket\n");
                netdev_fini();
		serval_fini();
		return -1;
	}
	
        ret = telnet_init();

        if (ret == -1) {
		LOG_ERR("Could not initialize telnet server\n");
                ctrl_fini();
                netdev_fini();
		serval_fini();
		return -1;
	}

	ret = server_run();

        telnet_fini();
	ctrl_fini();
	serval_fini();

	return ret;
}
