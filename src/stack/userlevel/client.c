/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/debug.h>
#include <scaffold/atomic.h>
#include <scaffold/timer.h>
#include <scaffold/net.h>
#include <scaffold_sock.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <userlevel/client.h>
#include <userlevel/client_msg.h>

struct client {
	client_type_t type;
	client_state_t state;
	int fd;
        struct socket *sock;
        struct client *parent;
	unsigned int id;
	int pipefd[2];
	int should_exit;
        pthread_t thr;
        sigset_t sigset;
	struct sockaddr_un sa;
	struct timer_list timer;
	struct list_head link;
        atomic_t refcnt;
        pthread_mutex_t lock;
};

static pthread_key_t client_key;
static pthread_once_t key_once = PTHREAD_ONCE_INIT;
extern atomic_t num_clients;
extern struct client_list client_list;

void client_destroy(struct client *c);

static void make_client_key(void)
{
	pthread_key_create(&client_key, NULL);
}

typedef int (*msg_handler_t)(struct client *, struct client_msg *);

static int dummy_msg_handler(struct client *c, struct client_msg *msg)
{
	LOG_DBG("Client %u handling message type %s\n", 
		c->id, client_msg_to_typestr(msg));

	return 0;
}

static int client_handle_bind_req_msg(struct client *c, struct client_msg *msg);
static int client_handle_connect_req_msg(struct client *c, struct client_msg *msg);
static int client_handle_listen_req_msg(struct client *c, struct client_msg *msg);
static int client_handle_accept2_req_msg(struct client *c, struct client_msg *msg);
static int client_handle_send_req_msg(struct client *c, struct client_msg *msg);
static int client_handle_close_req_msg(struct client *c, struct client_msg *msg);

msg_handler_t msg_handlers[] = {
	dummy_msg_handler,
	client_handle_bind_req_msg,
	dummy_msg_handler,
	client_handle_connect_req_msg,
	dummy_msg_handler,
	client_handle_listen_req_msg,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	client_handle_accept2_req_msg,
	dummy_msg_handler,
	client_handle_send_req_msg,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	client_handle_close_req_msg,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler
};
	
static void dummy_timer_callback(unsigned long data)
{
	LOG_DBG("Timer callback for client %u\n", 
                ((struct client *)data)->id);
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
  because we can "sleep" on it in a select()/poll().

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
        pthread_mutex_init(&c->lock, NULL);
        atomic_set(&c->refcnt, 1);

	return c;
}

void client_hold(struct client *c)
{
        atomic_inc(&c->refcnt);
}

void client_put(struct client *c)
{
        if (atomic_dec_and_test(&c->refcnt))
                client_destroy(c);        
}

int client_lock(struct client *c)
{
        return pthread_mutex_lock(&c->lock);
}

void client_unlock(struct client *c)
{
        pthread_mutex_unlock(&c->lock);
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
	int ret = 0;

        if (c->fd != -1) {
                ret = close(c->fd);
                c->fd = -1;
        }

        if (c->sock) {
                sock_release(c->sock);
                c->sock = NULL;
        }
	return ret;
}

void client_destroy(struct client *c)
{
        client_close(c);
	free(c);
}

int client_signal_pending(struct client *c)
{
        int ret;
        struct pollfd fds;

        fds.fd = c->pipefd[0];
        fds.events = POLLIN | POLLHUP;
        fds.revents = 0;

        ret = poll(&fds, 1, 0);
        
        if (ret == -1) {
                LOG_ERR("poll error: %s\n", strerror(errno));
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
		sz = read(c->pipefd[0], &r, 1);

		if (sz == 1)
			ret = 1;
	} while (sz > 0);

	return sz == -1 ? -1 : ret;
}

int client_handle_bind_req_msg(struct client *c, struct client_msg *msg)
{
	struct client_msg_bind_req *req = (struct client_msg_bind_req *)msg;
        struct client_msg_bind_rsp rsp;
        struct socket *sock = c->sock;
        struct sockaddr_sf saddr;
	int ret;
        
	LOG_DBG("bind request for service id %s\n", 
		service_id_to_str(&req->srvid));	

        memset(&saddr, 0, sizeof(saddr));
        saddr.sf_family = AF_SCAFFOLD;
        memcpy(&saddr.sf_srvid, &req->srvid, sizeof(req->srvid));

        ret = sock->ops->bind(sock, (struct sockaddr *)&saddr, sizeof(saddr));

        client_msg_hdr_init(&rsp.msghdr, MSG_BIND_RSP);
        memcpy(&rsp.srvid, &req->srvid, sizeof(req->srvid));
        
        if (ret < 0) {
                if (KERN_ERR(ret) == ERESTARTSYS) {
                        LOG_ERR("bind was interrupted\n");
                        rsp.error = EINTR;
                        return client_msg_write(c->fd, &rsp.msghdr);
                }
                LOG_ERR("bind failed: %s\n", KERN_STRERROR(ret));
                rsp.error = KERN_ERR(ret);
        }

	return client_msg_write(c->fd, &rsp.msghdr);
}

int client_handle_connect_req_msg(struct client *c, struct client_msg *msg)
{
	struct client_msg_connect_req *req = (struct client_msg_connect_req *)msg;
	struct client_msg_connect_rsp rsp;
        struct sockaddr_sf addr;
        int err;

	LOG_DBG("connect request for service id %s\n", 
		service_id_to_str(&req->srvid));

        memset(&addr, 0, sizeof(addr));
        addr.sf_family = AF_SCAFFOLD;
        memcpy(&addr.sf_srvid, &req->srvid, sizeof(req->srvid));

        err = c->sock->ops->connect(c->sock, (struct sockaddr *)&addr, 
                                    sizeof(req->srvid), req->flags); 

        client_msg_hdr_init(&rsp.msghdr, MSG_CONNECT_RSP);
        memcpy(&rsp.srvid, &req->srvid, sizeof(req->srvid));

        if (err < 0) {
                LOG_ERR("connect failed: %s\n", KERN_STRERROR(err));
                rsp.error = KERN_ERR(err);
        }

	return client_msg_write(c->fd, &rsp.msghdr);
}

int client_handle_listen_req_msg(struct client *c, struct client_msg *msg)
{
	struct client_msg_listen_req *req = (struct client_msg_listen_req *)msg;
        struct client_msg_listen_rsp rsp;
	int err;

	LOG_DBG("listen request, backlog=%u\n", req->backlog);
        
        err = c->sock->ops->listen(c->sock, req->backlog); 

        client_msg_hdr_init(&rsp.msghdr, MSG_LISTEN_RSP);

        if (err < 0) {
                LOG_ERR("listen failed: %s\n", KERN_STRERROR(err));
                rsp.error = KERN_ERR(err);
        }

	return client_msg_write(c->fd, &rsp.msghdr);
}

int client_handle_accept2_req_msg(struct client *c, struct client_msg *msg)
{
	struct client_msg_accept2_req *req = (struct client_msg_accept2_req *)msg;
        struct client_msg_accept2_rsp rsp;
        struct sock *psk;
        //struct sockaddr_un addr;
	int err, flags = 0;

	LOG_DBG("accept2 request\n");

        client_msg_hdr_init(&rsp.msghdr, MSG_ACCEPT2_RSP);

        /* Find parent sock */
        psk = scaffold_sock_lookup_serviceid(&req->srvid);

        if (!psk) {
                LOG_ERR("no parent sock\n");
                rsp.error = EOPNOTSUPP;
                goto out;
        }

        /* This is a bit ugly: we need to kill the "struct sock" that
         * was created as a result of creating the new client, and
         * then graft the new "struct sock" to the client socket when
         * we pull it from the accept queue.  This is because, when
         * clients are created, there is no way to initially know if
         * the client's sock will be a locally created socket or one
         * created as a result of accept().
         */
        sk_common_release(c->sock->sk);
        
        err = c->sock->ops->accept(psk->sk_socket, c->sock, flags); 

        if (err < 0) {
                LOG_ERR("accept2 failed: %s\n", KERN_STRERROR(err));
                rsp.error = KERN_ERR(err);
        }
out:
	return client_msg_write(c->fd, &rsp.msghdr);
}

int client_handle_send_req_msg(struct client *c, struct client_msg *msg)
{
	struct client_msg_send_req *req = (struct client_msg_send_req *)msg;
        DEFINE_CLIENT_RESPONSE(rsp, MSG_SEND_RSP);
        struct socket *sock = c->sock;
        struct msghdr mh;
        struct iovec iov;
        struct sockaddr_sf saddr;
        int ret;

        memset(&saddr, 0, sizeof(saddr));
        saddr.sf_family = AF_SCAFFOLD;
        memcpy(&saddr.sf_srvid, &req->srvid, sizeof(req->srvid));

        memset(&mh, 0, sizeof(mh));
        mh.msg_name = &saddr;
        mh.msg_namelen = sizeof(saddr);
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        
        iov.iov_base = req->data;
        iov.iov_len = req->data_len;

	LOG_DBG("data_len=%u\n", req->data_len);
        
        ret = sock->ops->sendmsg(NULL, sock, &mh, req->data_len);
        
        if (ret < 0) {
                rsp.error = KERN_ERR(ret);
                LOG_ERR("sendmsg returned error %s\n", KERN_STRERROR(ret));
        }
        
	return client_msg_write(c->fd, &rsp.msghdr);
}

int client_handle_close_req_msg(struct client *c, struct client_msg *msg)
{        
        DEFINE_CLIENT_RESPONSE(rsp, MSG_CLOSE_RSP);

        LOG_DBG("Sending close response\n");

        return client_msg_write(c->fd, &rsp.msghdr);
}

static int client_handle_msg(struct client *c)
{
	struct client_msg *msg;
	int ret;
	
	ret = client_msg_read(c->fd, &msg);

	if (ret < 1)
		return ret;

	ret = msg_handlers[msg->type](c, msg);

        if (ret == -1) {
                LOG_ERR("message handler error: %s\n", strerror(errno));
        }
        
	client_msg_free(msg);

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

		ret = select(nfds, &readfds, NULL, NULL, NULL);

		if (ret == -1) {
			if (errno == EINTR) {
				LOG_INF("client %u select interrupted\n", 
					c->id);
				continue;
			}
			/* Error */
			LOG_ERR("client %u select error...\n",
				c->id);
                        c->should_exit = 1;
			break;
		} else if (ret == 0) {
			/* Timeout */
			LOG_DBG("Client %u timeout\n", c->id);
		} else {
			if (FD_ISSET(c->pipefd[0], &readfds)) {
				/* Signal received, probably exit */
				LOG_DBG("Client %u exit signal\n", c->id);
                                c->should_exit = 1;
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

struct client *client_get_by_socket(struct socket *sock, struct client_list *list)
{
        struct client *c;

        client_list_lock(list);

        list_for_each_entry(c, &list->head, link) {
                if (c->sock == sock) {
                        client_list_unlock(list);
                        client_hold(c);
                        return c;
                }
        }

        client_list_unlock(list);
        
        return NULL;
}

void client_list_init(struct client_list *list)
{
        INIT_LIST_HEAD(&list->head);
        pthread_mutex_init(&list->mutex, NULL);
}

void client_list_add(struct client *c, struct client_list *list)
{	
        client_list_lock(list);
	list_add_tail(&c->link, &list->head);
        client_list_unlock(list);
}

void __client_list_del(struct client *c)
{
	list_del(&c->link);
}

void client_list_del(struct client *c, struct client_list *list)
{
        client_list_lock(list);
	list_del(&c->link);
        client_list_unlock(list);
}

int client_list_lock(struct client_list *list)
{
        return pthread_mutex_lock(&list->mutex);
}

void client_list_unlock(struct client_list *list)
{
        pthread_mutex_unlock(&list->mutex);
}

struct client *__client_list_first_entry(struct client_list *list)
{
	return list_first_entry(&list->head, struct client, link);
}

struct client *__client_list_entry(struct list_head *lh)
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
