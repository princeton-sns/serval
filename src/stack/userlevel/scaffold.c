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

LIST_HEAD(client_list);
static unsigned int num_clients = 0;
static int should_exit = 0;

void signal_handler(int sig)
{
        printf("signal caught! exiting...\n");
        should_exit = 1;       
}

struct client {
	int sock;
	int id;
	int pipefd[2];
	int should_exit;
        pthread_t thr;
        sigset_t mask;
	struct sockaddr_un sa;
	struct list_head link;
};

static struct client *client_create(int sock, struct sockaddr_un *sa, 
				    sigset_t *mask)
{
	struct client *c;

	c = (struct client *)malloc(sizeof(struct client));

	if (!c)
		return NULL;

	memset(c, 0, sizeof(struct client));
	
	c->sock = sock;
	c->id = num_clients++;
	c->should_exit = 0;
	memcpy(&c->sa, sa, sizeof(*sa));
	memcpy(&c->mask, mask, sizeof(*mask));
	
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
	char r = 'r';

	return read(c->pipefd[1], &r, 1);
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

static void *client_thread(void *arg)
{
	struct client *c = (struct client *)arg;

	while (!c->should_exit) {

	}

	client_close(c);

	return NULL;
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

static int server_run(void)
{	
	sigset_t mask, origmask;
	int server_sock, ret = 0;
	struct sockaddr_un sa;
	char buf[128];

        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGHUP);
        sigaddset(&mask, SIGINT);
	
        /* Block the signals we are watching here so that we can
         * handle them in pselect instead. */
        pthread_sigmask(SIG_BLOCK, &mask, &origmask);

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
	strcpy(sa.sun_path, "/tmp/scaffold.sock");
	
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

	while (!should_exit) {
		fd_set readfds;
                        
		FD_ZERO(&readfds);
		FD_SET(server_sock, &readfds);

		LOG_DBG("waiting for connection...\n");
		
		ret = pselect(server_sock + 1, &readfds, NULL, NULL, NULL, &origmask);
                
		if (ret == -1) {
			if (errno == EINTR) {
				LOG_INF("select interrupted\n");
				should_exit = 1;
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

				c = client_create(client_sock, &sa, &origmask);
				
				if (!c) {
					close(client_sock);
				} else {
					LOG_INF("accepted new client\n");
				}
				
				ret = client_start(c);

				if (ret == -1) {
					LOG_ERR("Could not start client\n");
					client_destroy(c);
				}
			}
		}
	}
	
	while (!list_empty(&client_list)) {
		struct client *c = list_entry(&client_list, struct client, link);
		
		client_signal_exit(c);
		LOG_INF("Joining with client %u\n", c->id);
		pthread_join(c->thr, NULL);
		client_destroy(c);
	}
out_close_sock:
	close(server_sock);
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
