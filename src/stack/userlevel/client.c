/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/debug.h>
#include <scaffold/timer.h>
#include <scaffold/net.h>
#include <scaffold_sock.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <userlevel/client.h>
#include <userlevel/msg_ipc.h>

struct client {
	client_type_t type;
	client_state_t state;
	int fd;
        struct socket *sock;
	unsigned int id;
	int pipefd[2];
	int should_exit;
        pthread_t thr;
        sigset_t sigset;
	struct sockaddr_un sa;
	struct timer_list timer;
	struct list_head link;
};

static pthread_key_t client_key;
static pthread_once_t key_once = PTHREAD_ONCE_INIT;

static void make_client_key(void)
{
	pthread_key_create(&client_key, NULL);
}

typedef int (*msg_handler_t)(struct client *, struct msg_ipc *);

static int dummy_msg_handler(struct client *c, struct msg_ipc *msg)
{
	LOG_DBG("Client %u handling message type %s\n", 
		c->id, msg_ipc_to_typestr(msg));

	return 0;
}

static int client_handle_bind_req_msg(struct client *c, struct msg_ipc *msg);
static int client_handle_connect_req_msg(struct client *c, struct msg_ipc *msg);

msg_handler_t msg_handlers[] = {
	dummy_msg_handler,
	client_handle_bind_req_msg,
	dummy_msg_handler,
	client_handle_connect_req_msg,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler
};
	
static void dummy_timer_callback(unsigned long data)
{
	struct client *c = (struct client *)data;
	LOG_DBG("Timer callback for client %u\n", c->id);
}

struct client *client_get_current(void)
{
        return (struct client *)pthread_getspecific(client_key); 
}

static inline int client_type_to_prot_type(client_type_t type)
{
        if (type == CLIENT_TYPE_UDP)
                return SOCK_DGRAM;
        if (type == CLIENT_TYPE_TCP)
                return SOCK_STREAM;
        
        return -1;
}

/*
  Create client.

  We use a pipe to signal to clients when to exit. A pipe is useful,
  because we can "sleep" on it in a select().

 */
struct client *client_create(client_type_t type, 
			     int sock, unsigned int id, 
			     struct sockaddr_un *sa,
			     sigset_t *sigset)
{
	struct client *c;
        int err;

	pthread_once(&key_once, make_client_key);

	c = (struct client *)malloc(sizeof(struct client));

	if (!c)
		return NULL;

	memset(c, 0, sizeof(struct client));
	
	c->type = type;
	c->state = CLIENT_STATE_NOT_RUNNING;
	c->fd = sock;

        err = sock_create(PF_SCAFFOLD, 
                          client_type_to_prot_type(type), 
                          0, &c->sock);
        if (err < 0) {
                LOG_ERR("Could not create socket: %s\n", KERN_STRERROR(err));
                free(c);
                return NULL;                        
        }

	c->id = id;
	LOG_DBG("client %p id is %u\n", c, c->id);
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

	/* Init a timer for test purposes. */
	c->timer.function = dummy_timer_callback;
	c->timer.expires = (id + 1) * 1000000;
	c->timer.data = (unsigned long)c;

	INIT_LIST_HEAD(&c->link);

	return c;
}

client_type_t client_get_type(struct client *c)
{
	return c->type;
}

client_state_t client_get_state(struct client *c)
{
	return c->state;
}

unsigned int client_get_id(struct client *c)
{
	return c->id;
}

pthread_t client_get_thread(struct client *c)
{
	return c->thr;
}

int client_get_sockfd(struct client *c)
{
        return c->fd;
}

int client_get_signalfd(struct client *c)
{
        return c->pipefd[0];
}

static int client_close(struct client *c)
{
	int ret;

	ret = close(c->fd);
	c->fd = -1;
        sock_release(c->sock);

	return ret;
}

void client_destroy(struct client *c)
{
	if (c->fd != -1)
		client_close(c);

	list_del(&c->link);
	free(c);
}

int client_signal_pending(struct client *c)
{
        int ret;
        fd_set readfds;
        struct timeval t = { 0, 0 };

        FD_ZERO(&readfds);
        FD_SET(c->pipefd[0], &readfds);
        
        ret = select(c->pipefd[0] + 1, &readfds, NULL, NULL, &t);
        
        if (ret == -1) {
                LOG_ERR("select error: %s\n", strerror(errno));
        }

        return ret;
}

int client_signal_raise(struct client *c)
{
	char w = 'w';

	return write(c->pipefd[1], &w, 1);
}

int client_signal_exit(struct client *c)
{
	c->should_exit = 1;
	return client_signal_raise(c);
}

int client_signal_lower(struct client *c)
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

int client_handle_bind_req_msg(struct client *c, struct msg_ipc *msg)
{
	struct msg_ipc_bind_req *br = (struct msg_ipc_bind_req *)msg;
	struct msg_ipc_bind_rsp rsp;
        struct socket *sock = c->sock;
        struct sockaddr_sf addr;
	int ret;
        
	LOG_DBG("bind request for service id %s\n", 
		service_id_to_str(&br->srvid));	

	msg_ipc_hdr_init(&rsp.msghdr, MSG_BIND_RSP);
        
        addr.ssf_family = AF_SCAFFOLD;
        memcpy(&addr.ssf_sid, &br->srvid, sizeof(br->srvid));

        ret = sock->ops->bind(sock, (struct sockaddr *)&addr, sizeof(addr));

        if (ret < 0) {
                if (KERN_ERR(ret) == ERESTARTSYS) {
                        LOG_ERR("Bind was interrupted\n");
                        rsp.error = EINTR;
                        return msg_ipc_write(c->fd, &rsp.msghdr);
                }
                LOG_ERR("Bind failed: %s\n", KERN_STRERROR(ret));
                rsp.error = KERN_ERR(ret);
                return msg_ipc_write(c->fd, &rsp.msghdr);
        }

        /* TODO: Bind should not return here... */
	return msg_ipc_write(c->fd, &rsp.msghdr);
}

int client_handle_connect_req_msg(struct client *c, struct msg_ipc *msg)
{
	struct msg_ipc_connect_req *cr = (struct msg_ipc_connect_req *)msg;
	
	LOG_DBG("connect request for service id %s\n", 
		service_id_to_str(&cr->srvid));	

	return 0;
}

static int client_handle_msg(struct client *c)
{
	struct msg_ipc *msg;
	int ret;
	
	ret = msg_ipc_read(c->fd, &msg);

	if (ret < 1)
		return ret;

	ret = msg_handlers[msg->type](c, msg);

        if (ret == -1) {
                LOG_ERR("message handler error: %s\n", strerror(errno));
        }
        
	msg_ipc_free(msg);

	return ret;
}

#define MAX(x, y) (x >= y ? x : y)

static void signal_handler(int signal)
{
        switch (signal) {
        case SIGPIPE:
                LOG_DBG("received SIGPIPE\n");
                break;
        default:
                LOG_DBG("signal %d received\n", signal);
        }
}

static void *client_thread(void *arg)
{
	struct sigaction action;
	struct client *c = (struct client *)arg;
	int ret;

	memset(&action, 0, sizeof(struct sigaction));
        action.sa_handler = signal_handler;
	sigaction(SIGPIPE, &action, 0);

	c->state = CLIENT_STATE_RUNNING;

	ret = pthread_setspecific(client_key, c);

	if (ret != 0) {
                LOG_ERR("Could not set client key\n");
		return NULL;
	}

#if defined(PER_THREAD_TIMER_LIST)
	if (timer_list_per_thread_init() == -1)
		return NULL;
#endif
	LOG_DBG("Client %u running\n", c->id);

	while (!c->should_exit) {
		fd_set readfds;
		int nfds;
		
		FD_ZERO(&readfds);
		FD_SET(c->pipefd[0], &readfds);

		if (c->fd != -1)
			FD_SET(c->fd, &readfds);

		nfds = MAX(c->fd, c->pipefd[0]) + 1;

		/* ret = pselect(nfds, &readfds, NULL, NULL, to, &c->sigset); */
		ret = pselect(nfds, &readfds, NULL, NULL, NULL, NULL);

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
		} else {
			if (FD_ISSET(c->pipefd[0], &readfds)) {
				/* Signal received, probably exit */
				client_signal_lower(c);
				LOG_DBG("Client %u exit signal\n", c->id);
				continue;
			}
			if (FD_ISSET(c->fd, &readfds)) {
				/* Socket readable */
				LOG_DBG("Client %u socket readable\n", c->id);
				ret = client_handle_msg(c);

				if (ret == 0) {
					/* Client close */
					LOG_DBG("Client %u closed\n", c->id);
					c->should_exit = 1;
				}
			} 
		}
	}

	LOG_DBG("Client %u exits\n", c->id);
	client_close(c);	
	c->state = CLIENT_STATE_GARBAGE;

	return NULL;
}

static void *test_client_thread(void *arg)
{
	struct client *c = (struct client *)arg;
#if defined(PER_THREAD_TIMER_LIST)
	if (timer_list_per_thread_init() == -1)
		return NULL;
#endif
	add_timer(&c->timer);

	return client_thread(arg);
}

int client_start(struct client *c)
{
	int ret;

	ret = pthread_create(&c->thr, NULL, client_thread, c);
        
        if (ret != 0) {
                LOG_ERR("could not start client thread\n");
        }

	return ret;
}

void client_list_add(struct client *c, struct list_head *head)
{	
	list_add_tail(&c->link, head);
}

void client_list_del(struct client *c)
{
	list_del(&c->link);
}

struct client *client_list_first_entry(struct list_head *head)
{
	return list_first_entry(head, struct client, link);
}

struct client *client_list_entry(struct list_head *lh)
{
	return list_entry(lh, struct client, link);
}

int test_client_start(struct client *c)
{
	int ret;

	ret = pthread_create(&c->thr, NULL, test_client_thread, c);
        
        if (ret != 0) {
                LOG_ERR("could not start client thread\n");
        }

	return ret;
}
