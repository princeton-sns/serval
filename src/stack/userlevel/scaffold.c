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
#include <errno.h>
#include <libgen.h>
#include <scaffold/platform.h>
#include <scaffold/debug.h>
#include <scaffold/list.h>
#include <scaffold/timer.h>
#include <af_scaffold.h>
#include <userlevel/client.h>

LIST_HEAD(client_list);
static unsigned int num_clients = 0;
static volatile int should_exit = 0;

#define MAX(x, y) (x >= y ? x : y)

void signal_handler(int sig)
{
        /* printf("signal caught! exiting...\n"); */
        should_exit = 1;       
}
#if 0
static int fd_make_async(int fd)
{
    int flags;
    
    if ((flags = fcntl(fd, F_GETFL, 0)) < 0) {
	    LOG_ERR("F_GETFL error on fd %d (%s)", fd,
		    strerror(errno));
        return -1;
    }
    
    flags |= O_NONBLOCK;

    if (fcntl(fd, F_SETFL, flags) < 0) {
	    LOG_ERR("F_SETFL error on fd %d (%s)", fd,
		    strerror(errno));
        return -1;
    }
    // close on exec
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
	    LOG_ERR("F_SETFD error on fd %d (%s)", fd,
		    strerror(errno));
        return -1;
    }

    return 0;
}
#endif

static void garbage_collect_clients(unsigned long data);
static DEFINE_TIMER(garbage_timer, garbage_collect_clients, 10000000, 0);

void garbage_collect_clients(unsigned long data)
{
	int num = 0;
	struct list_head *pos, *tmp;

	list_for_each_safe(pos, tmp, &client_list) {
		struct client *c = client_list_entry(pos);
		
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
			/* Destroying the client also removes it from
			 * the client list */
			client_destroy(c);
			num++;
		}
	}
	/* Schedule us again */
	add_timer(&garbage_timer);
}

#define NUM_SERVER_SOCKS 2
#define UDP_SERVER_PATH "/tmp/scaffold-udp.sock"
#define TCP_SERVER_PATH "/tmp/scaffold-tcp.sock"

static const char *server_sock_path[] = {
	UDP_SERVER_PATH,
	TCP_SERVER_PATH
};

static int server_run(void)
{	
	sigset_t sigset, orig_sigset;
	int server_sock[NUM_SERVER_SOCKS], i, ret = 0;
	struct sockaddr_un sa;

	sigemptyset(&sigset);
        sigaddset(&sigset, SIGTERM);
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGINT);
	
        /* Block the signals we are watching here so that we can
         * handle them in pselect instead. */
        sigprocmask(SIG_BLOCK, &sigset, &orig_sigset);
	
	if (should_exit)
		return 0;

	for (i = 0; i < NUM_SERVER_SOCKS; i++) {
		server_sock[i] = socket(AF_UNIX, SOCK_STREAM, 0);

		if (server_sock[i] == -1) {
			LOG_ERR("Failure. AF_UNIX server socket %s : %s\n", 
				server_sock_path[i], strerror(errno));
			return -1;
		}
		/* 
		ret = fd_make_async(server_sock[i]);
		
		if (ret == -1)
			goto out_close_socks;
		*/

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
#ifdef ENABLE_TEST_CLIENTS
	{
		/* Start some test clients */
		int i;
		for (i = 0; i < 3; i++) {
			struct client *c;
			
			c = client_create(CLIENT_TYPE_UDP, -1, 
					  num_clients++, &sa, &orig_sigset);
			
			if (!c)
				break;

			list_add_tail(&c->link, &client_list);

			ret = test_client_start(c);
		
			if (ret == -1) {
				LOG_ERR("Could not start client\n");
				client_destroy(c);
				break;
			}
		}
	}
#endif	
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

		ret = timer_list_get_next_timeout(&timeout);

		if (ret == -1) {
			/* Timer list error. Exit? */
			break;
		} else if (ret == 0) {
			/* No timer */
			to = NULL;
		} else {
			to = &timeout;
		}
		
		ret = pselect(maxfd + 1, &readfds, 
			      NULL, NULL, to, &orig_sigset);
                
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
		
		LOG_INF("client event\n");
		
		for (i = 0; i < NUM_SERVER_SOCKS; i++) {
			if (FD_ISSET(server_sock[i], &readfds)) {
				int client_sock;
				socklen_t addrlen = 0;
				struct client *c;
				
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
				c = client_create(i, client_sock, num_clients++, 
						  &sa, &orig_sigset);
				
				if (!c) {
					close(client_sock);
				} else {
					LOG_INF("accepted new client\n");
					
					client_list_add(c, &client_list);
					
					ret = client_start(c);
					
					if (ret == -1) {
						LOG_ERR("Could not start client\n");
						client_destroy(c);
					}
				}
			}
		}
	}
	
	while (!list_empty(&client_list)) {
		struct client *c = client_list_first_entry(&client_list);

		LOG_INF("Joining with client %u\n", client_get_id(c));
		client_signal_exit(c);

		if (pthread_join(client_get_thread(c), NULL) != 0) {
			if (errno == EINVAL) {
				LOG_DBG("Client %u probably detached\n", client_get_id(c));
			} else {
				LOG_ERR("Client %u could not be joined\n", client_get_id(c));
			}
		}
		client_destroy(c);
	}
out_close_socks:
	for (i = 0; i < NUM_SERVER_SOCKS; i++) {
		close(server_sock[i]);
		unlink(server_sock_path[i]);
	}
	return ret;
}

int main(int argc, char **argv)
{        
	struct sigaction action;
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

	ret = scaffold_init();

	if (ret == -1) {
		LOG_ERR("Could not initialize af_scaffold\n");
		return -1;
	}
	
	ret = server_run();

	scaffold_fini();

	return ret;
}
