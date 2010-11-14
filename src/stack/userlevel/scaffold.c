#include <stdlib.h>
#include <sys/types.h>  
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/select.h>
#include <errno.h>
#include <scaffold/platform.h>
#include <scaffold/debug.h>
#include <scaffold/list.h>
#include "timer.h"

LIST_HEAD(client_list);
static unsigned int num_clients = 0;
static volatile int should_exit = 0;

void signal_handler(int sig)
{
        printf("signal caught! exiting...\n");
        should_exit = 1;       
}

struct client {
	int sock;
	unsigned int id;
	int pipefd[2];
	int should_exit;
        pthread_t thr;
        sigset_t sigset;
	struct sockaddr_un sa;
	struct list_head link;
};

static struct client *client_create(int sock, struct sockaddr_un *sa, 
				    sigset_t *sigset)
{
	struct client *c;

	c = (struct client *)malloc(sizeof(struct client));

	if (!c)
		return NULL;

	memset(c, 0, sizeof(struct client));
	
	c->sock = sock;
	c->id = num_clients++;
	LOG_DBG("client id is %u\n", c->id);
	c->should_exit = 0;
	memcpy(&c->sa, sa, sizeof(*sa));

	if (sigset)
		memcpy(&c->sigset, sigset, sizeof(*sigset));
	
	if (pipe(c->pipefd) != 0) {
		LOG_ERR("could not open client pipe : %s\n",
			strerror(errno));
		free(c);
		return NULL;
	}
	
	INIT_LIST_HEAD(&c->link);
	list_add_tail(&c->link, &client_list);

	return c;
}

static int client_close(struct client *c)
{
	int ret;

	ret = close(c->sock);
	c->sock = -1;

	return ret;
}

static void client_destroy(struct client *c)
{
	if (c->sock)
		client_close(c);

	list_del(&c->link);
	free(c);
}

static int client_signal_raise(struct client *c)
{
	char w = 'w';

	return write(c->pipefd[1], &w, 1);
}

static int client_signal_exit(struct client *c)
{
	c->should_exit = 1;
	return client_signal_raise(c);
}

static int client_signal_lower(struct client *c)
{
	ssize_t sz;
	int ret = 0;
	char r = 'r';

	do {
		sz = read(c->pipefd[1], &r, 1);

		if (sz == 1)
			ret = 1;
	} while (sz > 0);

	return sz == -1 ? -1 : ret;
}

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

#define MAX(x, y) (x >= y ? x : y)

static void *client_thread(void *arg)
{
	struct client *c = (struct client *)arg;
	
	if (timer_list_per_thread_init(c->id) == -1)
		return NULL;
	
	LOG_DBG("Client %u running\n", c->id);

	while (!c->should_exit) {
		struct timespec timeout, *to = NULL;
		fd_set readfds;
		int ret, nfds;
		
		FD_ZERO(&readfds);
		FD_SET(c->sock, &readfds);
		FD_SET(c->pipefd[0], &readfds);
		nfds = MAX(c->sock, c->pipefd[0]) + 1;

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

		/* ret = pselect(nfds, &readfds, NULL, NULL, to, &c->sigset); */
		ret = pselect(nfds, &readfds, NULL, NULL, to, NULL);

		if (ret == -1) {
			if (errno == EINTR) {
				LOG_INF("client %u select interrupted\n", 
					c->id);
				continue;
			}
			/* Error */
			LOG_ERR("client %u select error...\n",
				c->id);
			break;
		} else if (ret == 0) {
			/* Timeout */
			LOG_DBG("Client %u timeout\n", c->id);
			timer_list_handle_timeout();
		} else {
			if (FD_ISSET(c->pipefd[0], &readfds)) {
				/* Signal received, probably exit */
				client_signal_lower(c);
				LOG_DBG("Client %u exit signal\n", c->id);
				continue;
			}
			if (FD_ISSET(c->sock, &readfds)) {
				/* Socket readable */
				LOG_DBG("Client %u socket readable\n", c->id);
			} 
		}
	}

	LOG_DBG("Client %u exits\n", c->id);
	client_close(c);

	return NULL;
}

static void test_timer_callback(unsigned long data)
{
	LOG_DBG("Test timer callback\n");
}

static DEFINE_TIMER(test_timer5s, test_timer_callback, 5000000, 2);
static DEFINE_TIMER(test_timer7s, test_timer_callback, 7000000, 2);
static DEFINE_TIMER(test_timer10s, test_timer_callback, 10000000, 2);

static void *test_client_thread(void *arg)
{
	struct client *c = (struct client *)arg;
	
	if (timer_list_per_thread_init(c->id) == -1)
		return NULL;

	add_timer(&test_timer7s);
	add_timer(&test_timer5s);
	add_timer(&test_timer10s);

	return client_thread(arg);
}

static int client_start(struct client *c)
{
	int ret;

	ret = pthread_create(&c->thr, NULL, client_thread, c);
        
        if (ret != 0) {
                LOG_ERR("could not start client thread\n");
        }

	return ret;
}
static int test_client_start(struct client *c)
{
	int ret;

	ret = pthread_create(&c->thr, NULL, test_client_thread, c);
        
        if (ret != 0) {
                LOG_ERR("could not start client thread\n");
        }

	return ret;
}

#define SERVER_PATH "/tmp/scaffold.sock"

static int server_run(void)
{	
	sigset_t sigset, orig_sigset;
	int server_sock, ret = 0;
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

	server_sock = socket(AF_UNIX, SOCK_STREAM, 0);

	if (server_sock == -1) {
		LOG_ERR("could not open AF_UNIX server socket : %s\n",
			strerror(errno));
		return -1;
	}

	ret = fd_make_async(server_sock);

	if (ret == -1)
		goto out_close_sock;
	
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, SERVER_PATH);
	
	ret = bind(server_sock, (struct sockaddr *)&sa, sizeof(sa));

	if (ret == -1) {
		LOG_ERR("bind failed for AF_UNIX socket : %s\n",
			strerror(errno));
		goto out_close_sock;
	}
	
	ret = listen(server_sock, 10);

	if (ret == -1) {
		LOG_ERR("listen failed for AF_UNIX socket : %s\n",
			strerror(errno));
		goto out_close_sock;
	}
	{
		/* Start a test client */
		struct client *c;

		c = client_create(-1, &sa, &orig_sigset);
		ret = test_client_start(c);
		
		if (ret == -1) {
			LOG_ERR("Could not start client\n");
			client_destroy(c);
		}
	}
				
	while (!should_exit) {
		fd_set readfds;
                        
		FD_ZERO(&readfds);
		FD_SET(server_sock, &readfds);

		LOG_DBG("waiting for connection...\n");
		
		ret = pselect(server_sock + 1, &readfds, NULL, NULL, NULL, &orig_sigset);
                
		if (ret == -1) {
			if (errno == EINTR) {
				LOG_INF("select interrupted\n");
				continue;
			}
			LOG_ERR("select error...\n");
			break;                                        
		}
		
		LOG_INF("incoming client\n");

		if (FD_ISSET(server_sock, &readfds)) {
			int client_sock;
			socklen_t addrlen;
			
			client_sock = accept(server_sock, 
					     (struct sockaddr *)&sa, &addrlen);
                        
			if (client_sock == -1) {
				LOG_ERR("accept() failed : %s\n", 
					strerror(errno));
			} else {
				struct client *c;

				c = client_create(client_sock, &sa, &orig_sigset);
				
				if (!c) {
					close(client_sock);
				} else {
					LOG_INF("accepted new client\n");
					
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
		struct client *c = list_first_entry(&client_list, 
						    struct client, link);
		LOG_INF("Joining with client %u\n", c->id);
		client_signal_exit(c);
		if (pthread_join(c->thr, NULL) != 0) {
			LOG_ERR("pthread_join failed for client %u\n", c->id);
		}
		client_destroy(c);
	}
out_close_sock:
	close(server_sock);
	unlink(SERVER_PATH);
	return ret;
}

int main(int argc, char **argv)
{        
	struct sigaction action;

	memset(&action, 0, sizeof(struct sigaction));
        action.sa_handler = signal_handler;
        
	/* The server should shut down on these signals. */
        sigaction(SIGTERM, &action, 0);
	sigaction(SIGHUP, &action, 0);
	sigaction(SIGINT, &action, 0);

	return server_run();
}
