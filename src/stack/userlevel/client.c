/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/debug.h>
#include <serval/atomic.h>
#include <serval/timer.h>
#include <serval/wait.h>
#include <serval/net.h>
#include <serval/bitops.h>
#include <serval_sock.h>
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
	int has_data;
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
	LOG_DBG("Client %u handling dummy message type %s\n",
		c->id, client_msg_to_typestr(msg));

	return 0;
}

static int client_handle_bind_req_msg(struct client *c, 
                                      struct client_msg *msg);
static int client_handle_connect_req_msg(struct client *c, 
                                         struct client_msg *msg);
static int client_handle_listen_req_msg(struct client *c, 
                                        struct client_msg *msg);
static int client_handle_accept_req_msg(struct client *c, 
                                        struct client_msg *msg);
static int client_handle_accept2_req_msg(struct client *c, 
                                         struct client_msg *msg);
static int client_handle_send_req_msg(struct client *c, 
                                      struct client_msg *msg);
static int client_handle_recv_req_msg(struct client *c, 
                                      struct client_msg *msg);
static int client_handle_close_req_msg(struct client *c, 
                                       struct client_msg *msg);
static int client_handle_clear_data_msg(struct client *c, 
                                        struct client_msg *msg);
static int client_handle_have_data_msg(struct client *c, 
                                       struct client_msg *msg);

msg_handler_t msg_handlers[] = {
	dummy_msg_handler,
	client_handle_bind_req_msg,
	dummy_msg_handler,
	client_handle_connect_req_msg,
	dummy_msg_handler,
	client_handle_listen_req_msg,
	dummy_msg_handler,
	client_handle_accept_req_msg,
	dummy_msg_handler,
	client_handle_accept2_req_msg,
	dummy_msg_handler,
	client_handle_send_req_msg,
	dummy_msg_handler,
	client_handle_recv_req_msg,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	dummy_msg_handler,
	client_handle_close_req_msg,
	dummy_msg_handler,
	dummy_msg_handler,
	client_handle_clear_data_msg,
	client_handle_have_data_msg
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
	c->has_data = 0;
	c->fd = sock;

        err = sock_create(PF_SERVAL,
                          client_type_to_prot_type(type),
                          0, &c->sock);
        if (err < 0) {
                LOG_ERR("Could not create socket: %s\n", KERN_STRERROR(err));
                free(c);
                return NULL;
        }
        
        c->id = id;
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

        /* Set non-blocking so that we can lower signal without
         * blocking */
        fcntl(c->pipefd[0], F_SETFL, O_NONBLOCK);

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
        pthread_mutex_destroy(&c->lock);
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

int client_signal_raise(struct client *c, enum client_signal s)
{
        /*char w = 'w';
          return write(c->pipefd[1], &w, 1); */
        uint8_t sig = s & 0xff;
        return write(c->pipefd[1], &sig, 1);
}

int client_signal_exit(struct client *c)
{
        c->should_exit = 1;
        return client_signal_raise(c, CLIENT_EXIT);
}

enum client_signal client_signal_lower(int fd)
{
        ssize_t sz;
        //int ret = 0;
        /*char r = 'r';*/
        uint8_t sig = 0;

        do {
                sz = read(fd, &sig, 1);

                /*if (sz == 1)
                  ret = 1; */
        } while (sz == 0);

        return (enum client_signal) (sz == -1 ? -1 : sig);
}

int client_handle_bind_req_msg(struct client *c, struct client_msg *msg)
{
        struct client_msg_bind_req *req = (struct client_msg_bind_req *)msg;
        struct client_msg_bind_rsp rsp;
        struct socket *sock = c->sock;
        struct sockaddr_sv saddr;
        int ret;

        LOG_DBG("Client %u bind request for service id %s\n", c->id,
                service_id_to_str(&req->srvid));	

        memset(&saddr, 0, sizeof(saddr));
        saddr.sv_family = AF_SERVAL;
        saddr.sv_flags = req->flags;
        saddr.sv_prefix_bits = req->prefix;
        memcpy(&saddr.sv_srvid, &req->srvid, sizeof(req->srvid));

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
        struct client_msg_connect_req *req = 
                (struct client_msg_connect_req *)msg;
        struct client_msg_connect_rsp rsp;
        struct sockaddr_sv addr;
        int err;

        LOG_DBG("Client %u connect request for service id %s\n", c->id,
                service_id_to_str(&req->srvid));

        memset(&addr, 0, sizeof(addr));
        addr.sv_family = AF_SERVAL;
        memcpy(&addr.sv_srvid, &req->srvid, sizeof(req->srvid));

        err = c->sock->ops->connect(c->sock, (struct sockaddr *)&addr, 
                                    sizeof(addr), req->flags); 

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

        LOG_DBG("Client %u listen request, backlog=%u\n", c->id, req->backlog);

        err = c->sock->ops->listen(c->sock, req->backlog); 

        client_msg_hdr_init(&rsp.msghdr, MSG_LISTEN_RSP);

        if (err < 0) {
                LOG_ERR("listen failed: %s\n", KERN_STRERROR(err));
                rsp.error = KERN_ERR(err);
        }

        return client_msg_write(c->fd, &rsp.msghdr);
}

/* 
   This function is called on the parent thread, i.e., the socket that
   is listening. We wait to be woken up, i.e., we wake when there is a
   new client socket in the accept queue.

   We respond to the application, which in turn creates a new client
   by opening a new IPC socket. This client is hooked up with the
   socket in the accept queue by calling accept2 below on the new
   client thread.
*/
int client_handle_accept_req_msg(struct client *c, struct client_msg *msg)
{
        //struct client_msg_accept_req *req = (struct client_msg_accept_req *)msg;
        struct client_msg_accept_rsp rsp;
        struct serval_sock *ssk = serval_sk(c->sock->sk);
        int err = 0;

        client_msg_hdr_init(&rsp.msghdr, MSG_ACCEPT_RSP);

        LOG_DBG("Client %u waiting for incoming request sleep=%p\n", c->id,
                sk_sleep(c->sock->sk));

        err = wait_event_interruptible(*sk_sleep(c->sock->sk), 
                                       !list_empty(&ssk->accept_queue));

        if (err < 0) {
                LOG_ERR("wait returned %d - %s\n", 
                        err, strerror(KERN_ERR(err)));
                rsp.error = KERN_ERR(err);
                goto out;
        }

        /* Write the service id of the parent in the response */
        memcpy(&rsp.local_srvid, &ssk->local_srvid, 
               sizeof(ssk->local_srvid));
        memcpy(&rsp.flowid, &ssk->local_flowid, 
               sizeof(ssk->local_flowid));

        LOG_DBG("parent service id=%s\n",
                service_id_to_str(&rsp.local_srvid));
 out:
        return client_msg_write(c->fd, &rsp.msghdr);
}
/* 
   Accept2 is called on the child thread, i.e., corresponding to the
   socket returned from accept().

   We need to hook up the client thread with the socket in the accept queue
   of the parent.
*/
int client_handle_accept2_req_msg(struct client *c, struct client_msg *msg)
{
        struct client_msg_accept2_req *req = 
                (struct client_msg_accept2_req *)msg;
        struct client_msg_accept2_rsp rsp;
        struct sock *psk;
        int err, flags = 0;

        LOG_DBG("Client %u accept2 request service id=%s\n", c->id,
                service_id_to_str(&req->srvid));

        client_msg_hdr_init(&rsp.msghdr, MSG_ACCEPT2_RSP);

        /* Find parent sock */
        psk = serval_sock_lookup_serviceid(&req->srvid);

        if (!psk) {
                LOG_ERR("no parent sock\n");
                rsp.error = EOPNOTSUPP;
                goto out;
        }

        /* This is a bit ugly: we need to kill the existing "struct
         * sock" associated with the client. This socket was created
         * as a result of creating the new client, because at that
         * time, there was no way to know whether the client's sock
         * would be a connection initiating sock or a result of
         * accept(). Then we graft the new "struct sock" to the client
         * socket when we pull it from the accept queue.
         */
        sk_common_release(c->sock->sk);
        c->sock->sk = NULL;

        err = c->sock->ops->accept(psk->sk_socket, c->sock, flags); 

        if (err < 0) {
                LOG_ERR("accept2 failed: %s\n", KERN_STRERROR(err));
                rsp.error = KERN_ERR(err);
        }
        sock_put(psk);
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
        struct {
                struct sockaddr_sv sv;
                struct sockaddr_in in;
        } addr;
        socklen_t addrlen = sizeof(addr.sv);
        int ret;
        
        memset(&addr, 0, sizeof(addr));
        addr.sv.sv_family = AF_SERVAL;
        memcpy(&addr.sv.sv_srvid, &req->srvid, sizeof(req->srvid));
        addr.in.sin_family = AF_INET;
        
        if (req->ipaddr != 0) {
                memcpy(&addr.in.sin_addr, &req->ipaddr,
                       sizeof(req->ipaddr));
                addrlen = sizeof(addr);
        }
        memset(&mh, 0, sizeof(mh));
        mh.msg_name = &addr;
        mh.msg_namelen = addrlen;
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        
        iov.iov_base = req->data;
        iov.iov_len = req->data_len;
        
#if defined(ENABLE_DEBUG)
        {
                struct in_addr ip;
                ip.s_addr = req->ipaddr;
                
                LOG_DBG("Client %u data_len=%u dest: %s @ %s\n", 
                        c->id, req->data_len, 
                        service_id_to_str(&req->srvid), 
                        inet_ntoa(ip));
        }
#endif
        ret = sock->ops->sendmsg(NULL, sock, &mh, req->data_len);
        
        if (ret < 0) {
                rsp.error = KERN_ERR(ret);
                LOG_ERR("sendmsg: %s\n", KERN_STRERROR(ret));
        }
        
	return client_msg_write(c->fd, &rsp.msghdr);
}

int client_handle_recv_req_msg(struct client *c, struct client_msg *msg)
{
	struct client_msg_recv_req *req = (struct client_msg_recv_req *)msg;
        struct {
                struct client_msg_recv_rsp rsp;
                unsigned char data[req->data_len];
        } r;
        struct socket *sock = c->sock;
        struct msghdr mh;
        struct iovec iov;

        struct {
                struct sockaddr_sv serv;
                struct sockaddr_in addr;
        } saddr;

        int ret;

        memset(&r, 0, sizeof(r));
        memset(&saddr, 0, sizeof(saddr));
        client_msg_hdr_init(&r.rsp.msghdr, MSG_RECV_RSP);
        memset(&mh, 0, sizeof(mh));
        memset(&iov, 0, sizeof(iov));
        memset(&saddr, 0, sizeof(saddr));
        mh.msg_name = &saddr;
        mh.msg_namelen = sizeof(saddr);
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        
        iov.iov_base = r.data;
        iov.iov_len = req->data_len;

        LOG_DBG("Client %u data_len=%u flags=%u\n", 
                c->id, req->data_len, req->flags);
        
        ret = sock->ops->recvmsg(NULL, sock, &mh, req->data_len, req->flags);
        
        if (ret < 0) {
                r.rsp.error = KERN_ERR(ret);
                LOG_ERR("recvmsg: %s\n", KERN_STRERROR(ret));
        } else {
                memcpy(&r.rsp.srvid, &saddr.serv.sv_srvid, 
                       sizeof(saddr.serv.sv_srvid));
                r.rsp.ipaddr = saddr.addr.sin_addr.s_addr;
                r.rsp.data_len = ret;
                r.rsp.msghdr.payload_length += ret;
                r.data[ret] = '\0';
        }
        
        LOG_DBG("Client %u read data len=%u\n", r.rsp.data_len);

        ret = client_msg_write(c->fd, &r.rsp.msghdr);
        
        return ret;
}

int client_handle_close_req_msg(struct client *c, struct client_msg *msg)
{        
        DEFINE_CLIENT_RESPONSE(rsp, MSG_CLOSE_RSP);
        int ret;
        
        LOG_DBG("Client %u closing socket %i\n", c->id, c->sock);
        ret = c->sock->ops->release(c->sock);

        if (ret < 0) {
                rsp.error = KERN_ERR(ret);
                LOG_ERR("release error %s\n", KERN_STRERROR(ret));
        } else {

        }

        client_msg_write(c->fd, &rsp.msghdr);

        return 0;
}

int client_handle_clear_data_msg(struct client *c, struct client_msg *msg)
{
        LOG_DBG("Client %u clearing has data: %i\n", c->id, c->has_data);
        c->has_data = 0;
        /* TODO - kludge to prevent client_thread from thinking no
           response data was written and should close */
        return 1;
}


int client_handle_have_data_msg(struct client *c, struct client_msg *msg)
{
        LOG_ERR("Client %u sent have data msg...error\n", c->id);
        return 0;
}

int client_send_have_data_msg(struct client *c)
{
        struct client_msg_have_data hd;
        
        LOG_DBG("Client %u sending have data msg to application\n", c->id);
        memset(&hd, 0, sizeof(hd));
        client_msg_hdr_init(&hd.msghdr, MSG_HAVE_DATA);
        return client_msg_write(c->fd, &hd.msghdr);
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
        DEFINE_WAIT(wait);

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
		enum client_signal csig;
		enum wait_signal wsig;

		FD_ZERO(&readfds);
		FD_SET(c->pipefd[0], &readfds);

		if (c->fd != -1)
			FD_SET(c->fd, &readfds);

		nfds = MAX(c->fd, c->pipefd[0]) + 1;
#if 0
                /*
                  This doesn't work well for me. It breaks normal wake
                  up. I think this should be implemented throught the
                  sock_wake_async() function in userlevel/socket.c
                */
		if (!c->has_data) {
                        /* wait for a data signal on the pipe
                         */
                        lock_sock(c->sock->sk);

                        /* TODO prevent bh from triggering writeable
                         * notifications all the time: let the wait
                         * flags dictate the interest notification
                         * sets
                         */
                        if (skb_peek(&c->sock->sk->sk_receive_queue)) {
                                /* data exists on the queue already */
                                release_sock(c->sock->sk);
                                c->has_data = 1;
                                client_send_have_data_msg(c);
                        }
                        else {
                                /* prepare_to_wait(sk_sleep(c->sock->sk), &wait, TASK_INTERRUPTIBLE); */
                                /* LOG_DBG("Adding wait queue fd %i to the client %u fd set\n", wait.pipefd[0], c->id); */
                                wait.flags &= ~WQ_FLAG_EXCLUSIVE;
                                pthread_mutex_lock(&sk_sleep(c->sock->sk)->lock);
                                if (list_empty(&wait.thread_list))
                                        list_add(&wait.thread_list, &sk_sleep(c->sock->sk)->thread_list);
                                pthread_mutex_unlock(&sk_sleep(c->sock->sk)->lock);

                                set_bit(SOCK_ASYNC_WAITDATA, &c->sock->sk->sk_socket->flags);
                                release_sock(c->sock->sk);

                                FD_SET(wait.pipefd[0], &readfds);
                                nfds = MAX(nfds, wait.pipefd[0] + 1);
                        }
		}
#endif /* 0 */
		ret = select(nfds, &readfds, NULL, NULL, NULL);

		if (ret == -1) {
			if (errno == EINTR)
                                continue;
			/* Error */
			LOG_ERR("client %u select error...\n",
				c->id);
                        c->should_exit = 1;
			break;
		} else if (ret == 0) {
			/* Timeout */
			/* LOG_DBG("Client %u timeout\n", c->id);*/
		} else {
                        /* LOG_DBG("Is wait queue fd set: %i, has data: %i\n", 
                           FD_ISSET(wait.pipefd[0], &readfds), c->has_data);*/

			if (FD_ISSET(c->pipefd[0], &readfds)) {
                                /* Signal received - determine message type
                                 * exit or data ready
                                 */
                                csig = client_signal_lower(c->pipefd[0]);

				/*LOG_DBG("Client %u signal received: %u\n", 
                                  c->id, sig); 
                                */

				if (csig < 0) {
                                        continue;
				}

				switch (csig) {
                                case CLIENT_EXIT:
				        c->should_exit = 1;
				        break;
				}

                                continue;
			}

			if (!c->has_data && FD_ISSET(wait.pipefd[0], &readfds)) {

                                wsig = wait_signal_lower(wait.pipefd[0]);

                                /* LOG_DBG("Client %u wait queue signal received: %u\n", c->id, sig); */

                                if (wsig < 0) {
                                        continue;
                                }

                                switch (wsig) {
			        case WAIT_READ_DATA:
                                        lock_sock(c->sock->sk);
                                        clear_bit(SOCK_ASYNC_WAITDATA, &c->sock->sk->sk_socket->flags);
                                        /* Don't destroy the wait until the end
                                         * finish_wait(sk_sleep(c->sock->sk), &wait); */

                                        if (!list_empty(&wait.thread_list)) {
                                                pthread_mutex_lock(&sk_sleep(c->sock->sk)->lock);
                                                list_del_init(&wait.thread_list);
                                                pthread_mutex_unlock(&sk_sleep(c->sock->sk)->lock);
                                        }

                                        release_sock(c->sock->sk);
                                        c->has_data = 1;
                                        client_send_have_data_msg(c);
                                        break;
			        case WAIT_WRITE_DATA:
                                        /* ignore socket writable*/
                                        break;
                                }
			}

			if (FD_ISSET(c->fd, &readfds)) {
				/* Socket readable */
				/* LOG_DBG("Client %u socket %i readable\n", c->id, c->fd); */
				ret = client_handle_msg(c);

				if (ret == 0) {
					/* Client close */
					LOG_DBG("Client %u closed\n", c->id);
					c->should_exit = 1;
				}
			} 
		}
	}

        destroy_wait(&wait);
	LOG_DBG("Client %u exiting\n", c->id);
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
