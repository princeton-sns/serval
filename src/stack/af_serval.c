/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/platform.h>
#if defined(OS_LINUX_KERNEL)
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <net/protocol.h>

#elif defined(OS_USER)
/* User-level declarations */
#include <errno.h>
#endif /* OS_LINUX_KERNEL */

/* Common includes */
#include <serval/debug.h>
#include <serval/list.h>
#include <serval/atomic.h>
#include <serval/wait.h>
#include <serval/sock.h>
#include <serval/net.h>
#include <serval/skbuff.h>
#include <serval/inet_sock.h>
#include <netinet/serval.h>
#include <serval_sock.h>
#include <serval_request_sock.h>
#include <serval_udp_sock.h>
#include <serval_tcp_sock.h>
#include <ctrl.h>

extern int __init packet_init(void);
extern void __exit packet_fini(void);
extern int __init service_init(void);
extern void __exit service_fini(void);
#if defined(OS_USER)
extern int __init neighbor_init(void);
extern void __exit neighbor_fini(void);
#endif

extern struct proto serval_udp_proto;
extern struct proto serval_tcp_proto;

int host_ctrl_mode = 0;

static struct sock *serval_accept_dequeue(struct sock *parent,
                                            struct socket *newsock);

/* Wait for the socket to reach or leave a specific state, depending
 * on the outofstate variable. It this variable is "true" the function
 * will wait until the socket leaves the given state, otherwise it
 * will wait until the given state is reached.
 */
static int serval_wait_state(struct sock *sk, int state,
                             long timeo, int outofstate)
{
	DECLARE_WAITQUEUE(wait, current);
	int err = 0;

        if (timeo < 0)
                timeo = MAX_SCHEDULE_TIMEOUT;

	add_wait_queue(sk_sleep(sk), &wait);

	while (1) {
                if (outofstate) {
                        if (sk->sk_state != state) {
                                LOG_DBG("outofstate: State is new=%s old=%s\n",
                                        serval_sock_state_str(sk),
                                        serval_state_str(state));
                                break;
                        }
                } else if (sk->sk_state == state) {
                        LOG_DBG("State is new=%s\n",
                                serval_sock_state_str(sk));
                        break;
                }
		set_current_state(TASK_INTERRUPTIBLE);

		if (!timeo) {
			err = -EINPROGRESS;
                        LOG_DBG("timeout 0 - EINPROGRESS\n");
			break;
		}

		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
                        LOG_DBG("Signal pending\n");
			break;
		}

		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);

		err = sock_error(sk);

		if (err) {
                        LOG_ERR("socket error %d\n", err);
			break;
                }
	}
	set_current_state(TASK_RUNNING);
	remove_wait_queue(sk_sleep(sk), &wait);
        UNDECLARE_WAITQUEUE(&wait);

	return err;
}

/*
  Automatically assigns a random service id.
*/
static int serval_autobind(struct sock *sk)
{
        struct serval_sock *ssk;
         /*
          Assign a random service id until the socket is assigned one
          with bind (if ever).

          TODO: check for conflicts.
        */
        lock_sock(sk);
        ssk = serval_sk(sk);
#if defined(OS_LINUX_KERNEL)
        get_random_bytes(&ssk->local_srvid, sizeof(struct service_id));
#else
        {
                unsigned int i;
                unsigned char *byte = (unsigned char *)&ssk->local_srvid;

                for (i = 0; i  < sizeof(struct service_id); i++) {
                        byte[i] = random() & 0xff;
                }
        }
#endif
        serval_sock_set_flag(ssk, SSK_FLAG_BOUND);
        serval_sock_set_flag(ssk, SSK_FLAG_AUTOBOUND);
        serval_sk(sk)->srvid_prefix_bits = 0;
        serval_sk(sk)->srvid_flags = 0;

        /* Add to protocol hash chains. */
        sk->sk_prot->hash(sk);

        release_sock(sk);

        return 0;
}

int serval_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
        struct sock *sk = sock->sk;
        struct serval_sock *ssk = serval_sk(sk);
        struct sockaddr_sv *svaddr = (struct sockaddr_sv *)addr;
        int ret = 0;

        if ((unsigned int)addr_len < sizeof(*svaddr))
                return -EINVAL;
        else if (addr_len % sizeof(*svaddr) != 0)
                return -EINVAL;

        LOG_INF("SERVAL bind on SID(%i:%i) %s\n", svaddr->sv_flags, svaddr->sv_prefix_bits, service_id_to_str(&svaddr->sv_srvid));


        /* Call the protocol's own bind, if it exists */
	if (sk->sk_prot->bind) {
                ret = sk->sk_prot->bind(sk, addr, addr_len);
                /* Add to protocol hash chains. */
                sk->sk_prot->hash(sk);

                return ret;
        }

        /* Notify the service daemon */
        if (!host_ctrl_mode) {
                struct ctrlmsg_register cm;
                cm.cmh.type = CTRLMSG_TYPE_REGISTER;
                cm.cmh.len = sizeof(cm);
                cm.sv_flags = svaddr->sv_flags;
                cm.sv_prefix_bits = svaddr->sv_prefix_bits;
                memcpy(&cm.srvid, &svaddr->sv_srvid, sizeof(svaddr->sv_srvid));
                ret = ctrl_sendmsg(&cm.cmh, GFP_KERNEL);

                if (ret < 0) {
                        LOG_INF("servd not running?\n");
                }
        }

        lock_sock(sk);

        /* Already bound? */
        if (serval_sock_flag(ssk, SSK_FLAG_BOUND)) {
                sk->sk_prot->unhash(sk);
        } else {
                /* Mark socket as bound */
                serval_sock_set_flag(ssk, SSK_FLAG_BOUND);
        }

        memcpy(&serval_sk(sk)->local_srvid, &svaddr->sv_srvid,
               sizeof(svaddr->sv_srvid));
        serval_sk(sk)->srvid_prefix_bits = svaddr->sv_prefix_bits;
        serval_sk(sk)->srvid_flags = svaddr->sv_flags;

        /* Hash socket */
        sk->sk_prot->hash(sk);

        release_sock(sk);

        return ret;
}

static int serval_listen_start(struct sock *sk, int backlog)
{
        serval_sock_set_state(sk, SERVAL_LISTEN);
        sk->sk_ack_backlog = 0;

        return 0;
}

static int serval_listen_stop(struct sock *sk)
{
        struct serval_sock *ssk = serval_sk(sk);

        /* Destroy queue of sockets that haven't completed three-way
         * handshake */
        while (1) {
                struct serval_request_sock *rsk;

                if (list_empty(&ssk->syn_queue))
                        break;

                rsk = list_first_entry(&ssk->syn_queue,
                                       struct serval_request_sock, lh);
                list_del(&rsk->lh);
                LOG_DBG("deleting SYN queued request socket\n");

                serval_rsk_free(rsk);
                sk->sk_ack_backlog--;
        }
        /* Destroy accept queue of sockets that completed three-way
           handshake (and send appropriate packets to other ends) */
        while (1) {
                struct serval_request_sock *rsk;

                if (list_empty(&ssk->accept_queue))
                        break;

                rsk = list_first_entry(&ssk->accept_queue,
                                       struct serval_request_sock, lh);
                list_del(&rsk->lh);

                if (rsk->sk) {
                        struct sock *child = rsk->sk;

                        /* From inet_connection_sock */
                        local_bh_disable();
                        bh_lock_sock(child);
                        /* WARN_ON(sock_owned_by_user(child)); */
                        sock_hold(child);

                        sk->sk_prot->disconnect(child, O_NONBLOCK);

                        /* Orphaning will mark the sock with flag DEAD,
                         * allowing the sock to be destroyed. */
                        sock_orphan(child);

                        LOG_DBG("removing socket from accept queue\n");

                        sk->sk_prot->unhash(child);
                        /* percpu_counter_inc(sk->sk_prot->orphan_count); */

                        /* put for rsk->sk pointer */
                        sock_put(child);

                        bh_unlock_sock(child);
                        local_bh_enable();

                        sock_put(child);
                }
                serval_rsk_free(rsk);
                sk->sk_ack_backlog--;
        }

        return 0;
}

static int serval_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
        int err = 0;

        lock_sock(sk);

        if (sock->type != SOCK_DGRAM && sock->type != SOCK_STREAM) {
                LOG_ERR("bad socket type\n");
                err = -EOPNOTSUPP;
                goto out;
        }

        if (sock->state != SS_UNCONNECTED) {
                LOG_ERR("socket not unconnected\n");
                err = -EINVAL;
                goto out;
        }

        if (!serval_sock_flag(serval_sk(sk), SSK_FLAG_BOUND) &&
            serval_autobind(sk) < 0)
		return -EAGAIN;
        /*
	if (!serval_sock_flag(serval_sk(sk), SSK_FLAG_BOUND)) {
                LOG_ERR("socket not BOUND\n");
                err = -EDESTADDRREQ;
                goto out;
        }
        */

        err = serval_listen_start(sk, backlog);

        if (err == 0) {
                sk->sk_max_ack_backlog = backlog;
        }
 out:
        release_sock(sk);

        return err;
}

struct sock *serval_accept_dequeue(struct sock *parent,
                                     struct socket *newsock)
{
	struct sock *sk = NULL;
        struct serval_sock *pssk = serval_sk(parent);
        struct serval_request_sock *rsk;

        /* Parent sock is already locked... */
        list_for_each_entry(rsk, &pssk->accept_queue, lh) {
                if (!rsk->sk)
                        continue;

                sk = rsk->sk;

                if (newsock) {
                        sock_graft(sk, newsock);
                        newsock->state = SS_CONNECTED;
                }

                list_del(&rsk->lh);
                serval_rsk_free(rsk);
                return sk;
        }

	return NULL;
}

static int serval_wait_for_connect(struct sock *sk, long timeo)
{
        struct serval_sock *ssk = serval_sk(sk);
	DEFINE_WAIT(wait);
	int err;

	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
		release_sock(sk);
		if (list_empty(&ssk->accept_queue))
			timeo = schedule_timeout(timeo);
		lock_sock(sk);
		err = 0;
		if (!list_empty(&ssk->accept_queue))
			break;
		err = -EINVAL;
		if (sk->sk_state != SERVAL_LISTEN)
			break;
		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			break;
		err = -EAGAIN;
		if (!timeo)
			break;
	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}

static int serval_accept(struct socket *sock, struct socket *newsock,
                           int flags)
{
	struct sock *sk = sock->sk, *nsk;
        struct serval_sock *ssk = serval_sk(sk);
	int err = 0;

	lock_sock(sk);

	if (sk->sk_state != SERVAL_LISTEN) {
		err = -EBADFD;
		goto out;
	}

        if (list_empty(&ssk->accept_queue)) {
                long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);

		/* If this is a non blocking socket don't sleep */
		err = -EAGAIN;

		if (!timeo)
			goto out;

                LOG_DBG("waiting for an incoming connect request\n");
		err = serval_wait_for_connect(sk, timeo);
                LOG_DBG("wait for incoming connect returned err=%d\n", err);

		if (err)
			goto out;
	}

        nsk = serval_accept_dequeue(sk, newsock);

        if (!nsk)
                err = -EAGAIN;
out:
	release_sock(sk);
        return err;
}

int serval_getname(struct socket *sock, struct sockaddr *addr,
		 int *addr_len, int peer)
{
        struct sockaddr_sv *sa = (struct sockaddr_sv *)addr;
        struct sock *sk = sock->sk;

	sa->sv_family  = AF_SERVAL;

	if (peer)
		memcpy(&sa->sv_srvid, &serval_sk(sk)->peer_srvid,
                       sizeof(struct sockaddr_sv));
	else
		memcpy(&sa->sv_srvid, &serval_sk(sk)->local_srvid,
                       sizeof(struct sockaddr_sv));

	*addr_len = sizeof(struct sockaddr_sv);

        return 0;
}

static int serval_connect(struct socket *sock, struct sockaddr *addr,
                            int alen, int flags)
{
        struct sock *sk = sock->sk;
        struct sockaddr_sv *svaddr = (struct sockaddr_sv *)addr;
        int err = 0;
        int nonblock = flags & O_NONBLOCK;

        if (addr->sa_family != AF_SERVAL) {
                LOG_ERR("bad address family\n");
                return -EAFNOSUPPORT;
        }

        lock_sock(sk);

        switch (sock->state) {
	default:
		err = -EINVAL;
		goto out;
	case SS_CONNECTED:
		err = -EISCONN;
		goto out;
	case SS_CONNECTING:
		err = -EALREADY;
		break;
	case SS_UNCONNECTED:
		err = -EISCONN;

		if (sk->sk_state == SERVAL_LISTEN)
			goto out;

                /* Set the peer address */
                memcpy(&serval_sk(sk)->peer_srvid, &svaddr->sv_srvid,
                       sizeof(struct service_id));

                /*
                  We need to rehash the socket because it may be
                  initially hashed on serviceID for being able to
                  receive unconnected datagrams
                */
                if (serval_sock_flag(serval_sk(sk), SSK_FLAG_BOUND))
                        sk->sk_prot->unhash(sk);

                serval_sock_set_state(sk, SERVAL_REQUEST);

                sk->sk_prot->hash(sk);

                err = sk->sk_prot->connect(sk, addr, alen);

		if (err < 0)
			goto out;

		sock->state = SS_CONNECTING;

		/* Just entered SS_CONNECTING state; the only
		 * difference is that return value in non-blocking
		 * case is EINPROGRESS, rather than EALREADY.
		 */
		err = -EINPROGRESS;
		break;
	}

        if (!nonblock) {
                /* Go to sleep, wait for timeout or successful connection */
                LOG_DBG("waiting for connect\n");
                err = serval_wait_state(sk, SERVAL_REQUEST, -1, 1);
                LOG_DBG("wait for connect returned=%d\n", err);
        } else {
                /* TODO: handle nonblocking connect */
                LOG_DBG("non-blocking connect\n");
                err = -EINPROGRESS;
                goto out;
        }

        if (sk->sk_state != SERVAL_CONNECTED)
                goto sock_error;

        sock->state = SS_CONNECTED;
out:
        release_sock(sk);

        return err;
sock_error:
	err = sock_error(sk) ? : -ECONNABORTED;
	sock->state = SS_UNCONNECTED;
	if (sk->sk_prot->disconnect(sk, flags))
		sock->state = SS_DISCONNECTING;
        goto out;
}

static int serval_sendmsg(struct kiocb *iocb, struct socket *sock,
                            struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;
        int err;

	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		return -EPIPE;

	/* We may need to bind the socket. */
	if (!serval_sock_flag(serval_sk(sk), SSK_FLAG_BOUND) &&
            serval_autobind(sk) < 0)
		return -EAGAIN;

	err = sk->sk_prot->sendmsg(iocb, sk, msg, size);

        return err;
}

static int serval_recvmsg(struct kiocb *iocb, struct socket *sock,
                            struct msghdr *msg,
                            size_t size, int flags)
{
	struct sock *sk = sock->sk;
	int addr_len = 0;
	int err;

	err = sk->sk_prot->recvmsg(iocb, sk, msg, size, flags & MSG_DONTWAIT,
				   flags & ~MSG_DONTWAIT, &addr_len);
	if (err >= 0)
		msg->msg_namelen = addr_len;

	return err;
}

static int serval_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	int err = 0;

	how++; /* maps 0->1 has the advantage of making bit 1 rcvs and
		       1->2 bit 2 snds.
		       2->3 */
	if ((how & ~SHUTDOWN_MASK) || !how)	/* MAXINT->0 */
		return -EINVAL;

	lock_sock(sk);

	if (sock->state == SS_CONNECTING) {
                /*
		if ((1 << sk->sk_state) &
		    (TCPF_SYN_SENT | TCPF_SYN_RECV | TCPF_CLOSE))
			sock->state = SS_DISCONNECTING;
		else
                */
                sock->state = SS_CONNECTED;
	}

	switch (sk->sk_state) {
	case SERVAL_CLOSED:
		err = -ENOTCONN;
		/* Hack to wake up other listeners, who can poll for
		   POLLHUP, even on eg. unconnected UDP sockets -- RR */
	default:
		sk->sk_shutdown |= how;
		if (sk->sk_prot->shutdown)
			sk->sk_prot->shutdown(sk, how);
		break;

	/* Remaining two branches are temporary solution for missing
	 * close() in multithreaded environment. It is _not_ a good idea,
	 * but we have no choice until close() is repaired at VFS level.
	 */
	case SERVAL_LISTEN:
		if (!(how & RCV_SHUTDOWN))
			break;
		/* Fall through */
	case SERVAL_REQUEST:
		err = sk->sk_prot->disconnect(sk, O_NONBLOCK);
		sock->state = err ? SS_DISCONNECTING : SS_UNCONNECTED;
		break;
	}

	/* Wake up anyone sleeping in poll. */
	sk->sk_state_change(sk);
	release_sock(sk);

        return err;
}

int serval_release(struct socket *sock)
{
        int err = 0;
        struct sock *sk = sock->sk;

        LOG_DBG("\n");

	if (sk) {
                int state;
                long timeout = 0;

                serval_shutdown(sock, 2);

		if (sock_flag(sk, SOCK_LINGER) && 0
                    /*!(current->flags & PF_EXITING) */)
			timeout = sk->sk_lingertime;

                sock->sk = NULL;

                lock_sock(sk);

                sk->sk_shutdown = SHUTDOWN_MASK;

                if (sk->sk_state == SERVAL_LISTEN) {
                        serval_listen_stop(sk);
                        serval_sock_set_state(sk, SERVAL_CLOSED);
                } else {
                        /* the protocol specific function called here
                         * should not lock sock */
                        sk->sk_prot->close(sk, timeout);
                }

                state = sk->sk_state;
                /* Hold reference so that the sock is not
                   destroyed by a bh when we release lock */
                sock_hold(sk);

                /* Orphaning will mark the sock with flag DEAD,
                 * allowing the sock to be destroyed. */
                sock_orphan(sk);

                release_sock(sk);

                /* Now socket is owned by kernel and we acquire BH lock
                   to finish close. No need to check for user refs.
                */
                local_bh_disable();
                bh_lock_sock(sk);

                /* Have we already been destroyed by a softirq or backlog? */
                if (state != SERVAL_CLOSED &&
                    sk->sk_state == SERVAL_CLOSED)
                        goto out;

                /* Other cleanup stuff goes here */

                if (sk->sk_state == SERVAL_CLOSED)
                        serval_sock_destroy(sk);
        out:
                bh_unlock_sock(sk);
                local_bh_enable();
                sock_put(sk);
        }

        return err;
}

#if defined(OS_LINUX_KERNEL)
static unsigned int serval_poll(struct file *file, struct socket *sock,
                                  poll_table *wait)
{
	struct sock *sk = sock->sk;
	unsigned int mask = 0;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	sock_poll_wait(file, sk_sleep(sk), wait);
#else
        poll_wait(file, sk->sk_sleep, wait);
#endif
        if (sk->sk_state == SERVAL_LISTEN) {
                struct serval_sock *ssk = serval_sk(sk);
                return list_empty(&ssk->accept_queue) ? 0 :
                        (POLLIN | POLLRDNORM);
        }

        mask = 0;

	if (sk->sk_err)
		mask = POLLERR;

	if (sk->sk_shutdown == SHUTDOWN_MASK ||
            sk->sk_state == SERVAL_CLOSED)
		mask |= POLLHUP;
	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= POLLIN | POLLRDNORM | POLLRDHUP;

	if ((1 << sk->sk_state) & ~(SERVALF_REQUEST | SERVALF_RESPOND)) {
                if (atomic_read(&sk->sk_rmem_alloc) > 0)
			mask |= POLLIN | POLLRDNORM;

		if (!(sk->sk_shutdown & SEND_SHUTDOWN)) {
			if (sk_stream_wspace(sk) >=
                            sk_stream_min_wspace(sk)) {
				mask |= POLLOUT | POLLWRNORM;
			} else {  /* send SIGIO later */
				set_bit(SOCK_ASYNC_NOSPACE,
					&sk->sk_socket->flags);
				set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);

				/* Race breaker. If space is freed after
				 * wspace test but before the flags are set,
				 * IO signal will be lost.
				 */
				if (sk_stream_wspace(sk) >=
                                    sk_stream_min_wspace(sk))
					mask |= POLLOUT | POLLWRNORM;
			}
		}
	}

	return mask;
}

static int serval_ioctl(struct socket *sock, unsigned int cmd,
                        unsigned long arg)
{
	struct sock *sk = sock->sk;
	int ret = 0;

        lock_sock(sk);

	switch (cmd) {
/*
		case SIOCSFMIGRATE:
                        if (sk->sk_state != SERVAL_CONNECTED) {
                                ret = -EINVAL;
                                break;
                        }
                        ret = sfnet_handle_migrate_socket(sk);
			break;
*/
		default:
			ret = -ENOIOCTLCMD;
			break;
	}

        release_sock(sk);

	return ret;
}
#endif

static const struct proto_ops serval_stream_ops = {
	.family =	PF_SERVAL,
	.owner =	THIS_MODULE,
	.release =	serval_release,
	.bind =		serval_bind,
	.connect =	serval_connect,
	.accept =	serval_accept,
	.getname =	serval_getname,
	.listen =	serval_listen,
	.shutdown =	serval_shutdown,
	.sendmsg =	serval_sendmsg,
	.recvmsg =	serval_recvmsg,
#if defined(OS_LINUX_KERNEL)
	.setsockopt =	sock_no_setsockopt,
	.getsockopt =	sock_no_getsockopt,
	.socketpair =	sock_no_socketpair,
	.poll =	        serval_poll,
	.ioctl =	serval_ioctl,
	.mmap =		sock_no_mmap,
	.sendpage =	sock_no_sendpage,
#if defined(ENABLE_SPLICE)
	/* .splice_read =  serval_tcp_splice_read, */
#endif
#endif
};

#if defined(OS_LINUX_KERNEL) && defined(ENABLE_SPLICE)
extern ssize_t serval_udp_splice_read(struct socket *sock, loff_t *ppos,
                                      struct pipe_inode_info *pipe, size_t len,
                                      unsigned int flags);
ssize_t serval_udp_sendpage(struct socket *sock, struct page *page, int offset,
                            size_t size, int flags);
#endif

static const struct proto_ops serval_dgram_ops = {
	.family =	PF_SERVAL,
	.owner =	THIS_MODULE,
	.release =	serval_release,
	.bind =		serval_bind,
	.connect =	serval_connect,
	.accept =	serval_accept,
	.getname =	serval_getname,
	.listen =	serval_listen,
	.shutdown =	serval_shutdown,
	.sendmsg =	serval_sendmsg,
	.recvmsg =	serval_recvmsg,
#if defined(OS_LINUX_KERNEL)
	.setsockopt =	sock_no_setsockopt,
	.getsockopt =	sock_no_getsockopt,
	.socketpair =	sock_no_socketpair,
	.poll =	        serval_poll,
	.ioctl =	serval_ioctl,
	.mmap =		sock_no_mmap,
#if defined(ENABLE_SPLICE) && (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
	.splice_read =  serval_udp_splice_read,
	.sendpage =	serval_udp_sendpage,
#else
	.sendpage =	sock_no_sendpage,
#endif
#endif
};

/**
   Create a new Serval socket.
 */
static int serval_create(struct net *net, struct socket *sock, int protocol
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
                           , int kern
#endif
)
{
        struct sock *sk = NULL;
        struct inet_sock *inet = NULL;
        int ret = 0;

        LOG_DBG("Creating SERVAL socket\n");

        if (protocol &&
            (protocol != SERVAL_PROTO_UDP &&
             protocol != SERVAL_PROTO_TCP))
		return -EPROTONOSUPPORT;

	sock->state = SS_UNCONNECTED;

	switch (sock->type) {
                case SOCK_DGRAM:
                        if (!protocol)
                                protocol = SERVAL_PROTO_UDP;
                        sock->ops = &serval_dgram_ops;
                        sk = serval_sk_alloc(net, sock,
                                               GFP_KERNEL,
                                               protocol,
                                               &serval_udp_proto);
                        break;
                case SOCK_STREAM:
                        if (!protocol)
                                protocol = SERVAL_PROTO_TCP;
                        sock->ops = &serval_stream_ops;
                        sk = serval_sk_alloc(net, sock,
                                               GFP_KERNEL,
                                               protocol,
                                               &serval_tcp_proto);
                        break;
                case SOCK_SEQPACKET:
                case SOCK_RAW:
                default:
                        return -ESOCKTNOSUPPORT;
	}

	if (!sk) {
                ret = -ENOMEM;
		goto out;
        }

        /* Initialize serval sock part of socket */
        serval_sock_init(sk);

        /* Initialize inet part */
        inet = inet_sk(sk);
	inet->uc_ttl	= -1; /* Let IP decide TTL */
#if defined(OS_LINUX_KERNEL)
	inet->mc_loop	= 1;
	inet->mc_ttl	= 1;
	inet->mc_all	= 1;
	inet->mc_index	= 0;
	inet->mc_list	= NULL;
#endif

        if (sk->sk_prot->init) {
                /* Call protocol specific init */
                ret = sk->sk_prot->init(sk);

		if (ret < 0)
			sk_common_release(sk);
	}
out:
        return ret;
}

static struct net_proto_family serval_family_ops = {
	.family = PF_SERVAL,
	.create = serval_create,
	.owner	= THIS_MODULE,
};

int __init serval_init(void)
{
        int err = 0;

#if defined(OS_USER)
        err = neighbor_init();

        if (err < 0) {
                LOG_CRIT("Cannot initialize neighbor table\n");
                goto fail_neighbor;
        }
#endif
        err = service_init();

        if (err < 0) {
                LOG_CRIT("Cannot initialize service table\n");
                goto fail_service;
        }

        err = serval_sock_tables_init();

        if (err < 0) {
                  LOG_CRIT("Cannot initialize serval sockets\n");
                  goto fail_sock;
        }

        err = packet_init();

        if (err != 0) {
		LOG_CRIT("Cannot init packet socket!\n");
		goto fail_packet;
	}

        err = proto_register(&serval_udp_proto, 1);

	if (err != 0) {
		LOG_CRIT("Cannot create serval_sock SLAB cache!\n");
		goto fail_proto;
	}

        err = sock_register(&serval_family_ops);

        if (err != 0) {
                LOG_CRIT("Cannot register socket family\n");
                goto fail_sock_register;
        }
out:
        return err;

	sock_unregister(PF_SERVAL);
fail_sock_register:
	proto_unregister(&serval_udp_proto);
fail_proto:
        packet_fini();
fail_packet:
        serval_sock_tables_fini();
fail_sock:
        service_fini();
fail_service:
#if defined(OS_USER)
        neighbor_fini();
fail_neighbor:
#endif
        goto out;
}

#if defined(OS_LINUX_KERNEL)
#include <net/ip.h>
#endif

void __exit serval_fini(void)
{
     	sock_unregister(PF_SERVAL);
	proto_unregister(&serval_udp_proto);
        packet_fini();
        serval_sock_tables_fini();
        service_fini();
#if defined(OS_USER)
        neighbor_fini();
#endif
}
