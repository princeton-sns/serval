/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/platform.h>
#if defined(OS_LINUX_KERNEL)
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/string.h>
#include <net/protocol.h>

#elif defined(OS_USER)
/* User-level declarations */
#include <errno.h>
#endif /* OS_LINUX_KERNEL */

/* Common includes */
#include <scaffold/debug.h>
#include <scaffold/list.h>
#include <scaffold/atomic.h>
#include <scaffold/wait.h>
#include <scaffold/sock.h>
#include <scaffold/net.h>
#include <scaffold/skbuff.h>
#include <netinet/scaffold.h>
#include <scaffold_sock.h>
#include <scaffold_request_sock.h>
#include <scaffold_udp_sock.h>
#include <scaffold_tcp_sock.h>
#include <ctrl.h>

extern int __init packet_init(void);
extern void __exit packet_fini(void);
extern int __init service_init(void);
extern void __exit service_fini(void);

extern struct proto scaffold_udp_proto;
extern struct proto scaffold_tcp_proto;

static atomic_t scaffold_nr_socks = ATOMIC_INIT(0);
static atomic_t scaffold_sock_id = ATOMIC_INIT(1);
int host_ctrl_mode = 0;

static struct sock *scaffold_sk_alloc(struct net *net, struct socket *sock, 
                                      gfp_t priority, int protocol, 
                                      struct proto *prot);

static struct sock *scaffold_accept_dequeue(struct sock *parent, 
                                            struct socket *newsock);
/* Wait for the socket to reach a specific state. */
int scaffold_wait_state(struct sock *sk, int state, unsigned long timeo)
{
	DECLARE_WAITQUEUE(wait, current);
	int err = 0;

	add_wait_queue(sk_sleep(sk), &wait);

	while (sk->sk_state != state) {
		set_current_state(TASK_INTERRUPTIBLE);

		if (!timeo) {
			err = -EINPROGRESS;
			break;
		}

		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			break;
		}

		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);

		err = sock_error(sk);

		if (err)
			break;
	}
	set_current_state(TASK_RUNNING);
	remove_wait_queue(sk_sleep(sk), &wait);

	return err;
}

static int __scaffold_assign_sockid(struct sock *sk)
{
        struct scaffold_sock *ssk = scaffold_sk(sk);
       
        /* 
           TODO: 
           - Check for ID wraparound and conflicts 
           - Make sure code does not assume sockid is a short
        */
        ssk->sockid.s_id = htons(atomic_inc_return(&scaffold_sock_id));
        return 0;
}

/*
  Automatically assigns a random service id.
*/
static int scaffold_autobind(struct sock *sk)
{
        struct scaffold_sock *ssk;
         /*
          Assign a random service id until the socket is assigned one
          with bind (if ever).

          TODO: check for conflicts.
        */
        lock_sock(sk);
        ssk = scaffold_sk(sk);
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
        scaffold_sock_set_flag(ssk, SSK_FLAG_BOUND);

        /* Add to protocol hash chains. */
        sk->sk_prot->hash(sk);

        release_sock(sk);

        return 0;
}

int scaffold_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
        struct sock *sk = sock->sk;
        //struct scaffold_sock *ssk = scaffold_sk(sk);
        struct sockaddr_sf *sfaddr = (struct sockaddr_sf *)addr;
        int ret = 0, cond = 1;
        
        if ((unsigned int)addr_len < sizeof(*sfaddr))
                return -EINVAL;
        else if (addr_len % sizeof(*sfaddr) != 0)
                return -EINVAL;
        
        /* Call the protocol's own bind, if it exists */
	if (sk->sk_prot->bind) {
                ret = sk->sk_prot->bind(sk, addr, addr_len);
                /* Add to protocol hash chains. */
                sk->sk_prot->hash(sk);

                return ret;
        }
        lock_sock(sk);

        LOG_DBG("handling bind\n");

        if (host_ctrl_mode) {
                ret = 1;
                scaffold_sock_set_flag(scaffold_sk(sk), SSK_FLAG_BOUND);
        } else {
                struct ctrlmsg_register cm;
                cm.cmh.type = CTRLMSG_TYPE_REGISTER;
                cm.cmh.len = sizeof(cm);
                memcpy(&cm.srvid, &sfaddr->sf_srvid, sizeof(sfaddr->sf_srvid));
                ret = ctrl_sendmsg(&cm.cmh, GFP_KERNEL);
        }
        if (ret < 0) {
                LOG_ERR("bind failed, scafd not running?\n");
                release_sock(sk);
                return ret;
        }

        memcpy(&scaffold_sk(sk)->local_srvid, &sfaddr->sf_srvid, 
               sizeof(sfaddr->sf_srvid));
        /* 
           Return value of 1 indicates we are in controller mode -->
           do not wait for a reply 
        */
        if (ret == 1) {
                LOG_DBG("in controller mode\n");
                /* Add to protocol hash chains. */
                sk->sk_prot->hash(sk);

                release_sock(sk);
                ret = 0;
        } else if (ret == 0) {
                release_sock(sk);
                /* Sleep and wait for response or timeout */
                ret = wait_event_interruptible_timeout(*sk_sleep(sk), 
                                                       cond != 1, 
                                                       msecs_to_jiffies(5000));

                if (ret < 0) {
                        if (ret == -ERESTARTSYS) {
                                LOG_ERR("bind interrupted\n");
                        } else {
                                LOG_ERR("wait failed\n");
                        }
                } else if (ret == 0) {
                        LOG_DBG("bind timeout\n");
                        ret = -ETIMEDOUT;
                } else  {
                        ret = cond;
                        LOG_DBG("bind returned %d\n", ret);
                        
                        lock_sock(sk);

                        /* Add to protocol hash chains. */
                        sk->sk_prot->hash(sk);

                        release_sock(sk);
                }
        } else {
                release_sock(sk);
        }
        return ret;
}

static int scaffold_listen_start(struct sock *sk, int backlog)
{
        //struct scaffold_sock *ssk = scaffold_sk(sk);

        /* Unhash the socket since we need to hash it into listen table */
        sk->sk_prot->unhash(sk);
        /* TODO: create accept queue */
        scaffold_sock_set_state(sk, SCAFFOLD_LISTEN);
        sk->sk_ack_backlog = 0;
        
        /* Hash it on the service id. This will put the socket in
           another hash table than the initial hashing on socket
           id. */

        sk->sk_prot->hash(sk);

        return 0;
}

static int scaffold_listen_stop(struct sock *sk)
{
        struct scaffold_sock *ssk = scaffold_sk(sk);
        
        /* Destroy queue of sockets that haven't completed three-way
         * handshake */
        while (1) {
                struct scaffold_request_sock *rsk;
                
                if (list_empty(&ssk->syn_queue))
                        break;
                
                rsk = list_first_entry(&ssk->syn_queue, 
                                       struct scaffold_request_sock, lh);
                list_del(&rsk->lh);
                scaffold_rsk_free(rsk);
                sk->sk_ack_backlog--;
        }
        /* Destroy accept queue of sockets that completed three-way
           handshake (and send appropriate packets to other ends) */
        while (1) {
                struct scaffold_request_sock *rsk;

                if (list_empty(&ssk->accept_queue))
                        break;
                
                rsk = list_first_entry(&ssk->accept_queue, 
                                       struct scaffold_request_sock, lh);
                list_del(&rsk->lh);

                if (rsk->sk) {
                        struct sock *child = rsk->sk;
                        
                        /* From inet_connection_sock */
                        local_bh_disable();
                        bh_lock_sock(child);
                        /* WARN_ON(sock_owned_by_user(child)); */
                        sock_hold(child);

                        sk->sk_prot->disconnect(child, O_NONBLOCK);

                        sock_orphan(child);

                        /* percpu_counter_inc(sk->sk_prot->orphan_count); */

                        bh_unlock_sock(child);
                        local_bh_enable();
                        sock_put(child);
                }
                scaffold_rsk_free(rsk);
                sk->sk_ack_backlog--;
        }
     
        return 0;
}

static int scaffold_listen(struct socket *sock, int backlog)
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
        
	if (!scaffold_sock_flag(scaffold_sk(sk), SSK_FLAG_BOUND)) {
                LOG_ERR("socket not BOUND\n");
                err = -EDESTADDRREQ;
                goto out;
        }

        err = scaffold_listen_start(sk, backlog);

        if (err == 0) {
                sk->sk_max_ack_backlog = backlog;
        }
 out:
        release_sock(sk);

        return err;
}

struct sock *scaffold_accept_dequeue(struct sock *parent, 
                                     struct socket *newsock)
{
	struct sock *sk = NULL;
        struct scaffold_sock *pssk = scaffold_sk(parent);
        struct scaffold_request_sock *rsk;

        /* Parent sock is already locked... */
        list_for_each_entry(rsk, &pssk->accept_queue, lh) {
                /* struct scaffold_sock *ssk; */
                
                /*
                switch (newsock->type) {
                case SOCK_DGRAM:
                //newsock->ops = &scaffold_dgram_ops;
                        sk = scaffold_sk_alloc(sock_net(parent), newsock, 
                                               GFP_KERNEL, 
                                               parent->sk_protocol,
                                               &scaffold_udp_proto);
                        break;
                case SOCK_STREAM: 
                        //newsock->ops = &scaffold_stream_ops;
                        sk = scaffold_sk_alloc(sock_net(parent), newsock, 
                                               GFP_KERNEL,
                                               parent->sk_protocol,
                                               &scaffold_tcp_proto);
                        break;
                case SOCK_SEQPACKET:	
                case SOCK_RAW:
                default:
                        return NULL;
                }
                */
                if (!rsk->sk)
                        continue;

                sk = rsk->sk;

                list_del(&rsk->lh);
                

                /* Inherit the service id from the parent socket */
                /*
                  ssk = scaffold_sk(sk);
                memcpy(&ssk->local_srvid, 
                       &pssk->local_srvid, 
                       sizeof(pssk->local_srvid));
                
                memcpy(&ssk->peer_srvid, &rsk->peer_srvid, sizeof(rsk->peer_srvid));
                memcpy(&ssk->dst_flowid, &rsk->dst_flowid, sizeof(rsk->dst_flowid));
                ssk->tot_bytes_sent = 0;
                */
                scaffold_rsk_free(rsk);

                lock_sock(sk);
               
                if (newsock) {
                        sock_graft(sk, newsock);
                        newsock->state = SS_CONNECTED;
                }
                                
                atomic_inc(&scaffold_nr_socks);

                /* Make available */
                sk->sk_prot->hash(sk);

                release_sock(sk);
                
                return sk;
        }

	return NULL;
}

static int scaffold_wait_for_connect(struct sock *sk, long timeo)
{
        struct scaffold_sock *ssk = scaffold_sk(sk);
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
		if (sk->sk_state != SCAFFOLD_LISTEN)
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

static int scaffold_accept(struct socket *sock, struct socket *newsock, 
                           int flags)
{
	struct sock *sk = sock->sk, *nsk;
        struct scaffold_sock *ssk = scaffold_sk(sk);
	int err = 0;

	lock_sock(sk);

	if (sk->sk_state != SCAFFOLD_LISTEN) {
		err = -EBADFD;
		goto out;
	}

        if (list_empty(&ssk->accept_queue)) {
                long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);
                
		/* If this is a non blocking socket don't sleep */
		err = -EAGAIN;
		if (!timeo)
			goto out;

		err = scaffold_wait_for_connect(sk, timeo);
                
		if (err)
			goto out;
	}
	
        nsk = scaffold_accept_dequeue(sk, newsock);

        if (!nsk)
                err = -EAGAIN;
out:
	release_sock(sk);
        return err;
}

int scaffold_getname(struct socket *sock, struct sockaddr *addr,
		 int *addr_len, int peer)
{
        struct sockaddr_sf *sa = (struct sockaddr_sf *)addr;
        struct sock *sk = sock->sk;

	sa->sf_family  = AF_SCAFFOLD;

	if (peer)
		memcpy(&sa->sf_srvid, &scaffold_sk(sk)->peer_srvid, 
                       sizeof(struct sockaddr_sf));
	else
		memcpy(&sa->sf_srvid, &scaffold_sk(sk)->local_srvid, 
                       sizeof(struct sockaddr_sf));

	*addr_len = sizeof(struct sockaddr_sf);

        return 0;
}

static int scaffold_connect(struct socket *sock, struct sockaddr *addr,
                            int alen, int flags)
{
        struct sock *sk = sock->sk;
        struct sockaddr_sf *sfaddr = (struct sockaddr_sf *)addr;
        int err = 0, connect_ret = 1;
        int nonblock = flags & O_NONBLOCK;

        if (addr->sa_family != AF_SCAFFOLD)
                return -EAFNOSUPPORT;
        
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
                /*
		if (sk->sk_state != SCAFFOLD_CLOSED)
			goto out;
                */
                /* Set the peer address */
                memcpy(&scaffold_sk(sk)->peer_srvid, &sfaddr->sf_srvid, 
                       sizeof(struct service_id));

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

        LOG_DBG("waiting for connect\n");

        if (!nonblock) {
                /* Go to sleep, wait for timeout or successful connection */
                release_sock(sk);
                err = wait_event_interruptible_timeout(*sk_sleep(sk), 
                                                       connect_ret != 1,
                                                       msecs_to_jiffies(5000));
                lock_sock(sk);

                /* Check if we were interrupted */
                if (err == 0) {
                        if (connect_ret == 0) {
                                LOG_DBG("connect returned, connect_ret=%d\n", connect_ret);
                                
                                if (connect_ret == 0) {
                                        sock->state = SS_CONNECTED;
                                        err = 0;
                                }
                        } else {
                                LOG_ERR("connect() wait for BOUND failed, connect_ret=%d\n", connect_ret);
                                err = connect_ret;
                        }
                }
        }
        if (sk->sk_state != SCAFFOLD_CONNECTED)
                goto sock_error;
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
static int scaffold_sendmsg(struct kiocb *iocb, struct socket *sock, 
                            struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;

	/* We may need to bind the socket. */
	if (sk->sk_state == SCAFFOLD_CLOSED && scaffold_autobind(sk) < 0)
		return -EAGAIN;

	return sk->sk_prot->sendmsg(iocb, sk, msg, size);
}

static int scaffold_recvmsg(struct kiocb *iocb, struct socket *sock, 
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

static int scaffold_shutdown(struct socket *sock, int how)
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
	case SCAFFOLD_CLOSED:
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
	case SCAFFOLD_LISTEN:
		if (!(how & RCV_SHUTDOWN))
			break;
		/* Fall through */
	case SCAFFOLD_REQUEST:
		err = sk->sk_prot->disconnect(sk, O_NONBLOCK);
		sock->state = err ? SS_DISCONNECTING : SS_UNCONNECTED;
		break;
	}

	/* Wake up anyone sleeping in poll. */
	sk->sk_state_change(sk);
	release_sock(sk);

        return err;
}

int scaffold_release(struct socket *sock)
{
        int err = 0;
        struct sock *sk = sock->sk;

	if (sk) {
                long timeout;
                
                scaffold_shutdown(sock, 2);

                sock_orphan(sk);
                
                LOG_DBG("SCAFFOLD socket %p released, refcnt=%d, tot_bytes_sent=%lu\n", 
                        sk, atomic_read(&sk->sk_refcnt) - 1, 
                        scaffold_sk(sk)->tot_bytes_sent);
                
		timeout = 0;

		if (sock_flag(sk, SOCK_LINGER) && 0
                    /*!(current->flags & PF_EXITING) */)
			timeout = sk->sk_lingertime;
		
                sock->sk = NULL;
                
                lock_sock(sk);

                if (sk->sk_state == SCAFFOLD_LISTEN) {
                        /* Should unregister. */
                        scaffold_listen_stop(sk);
                }
                
                scaffold_sock_set_state(sk, SCAFFOLD_CLOSED);
                
                /* cannot lock sock in protocol specific functions */
                sk->sk_prot->close(sk, timeout);

                release_sock(sk);

                sk_common_release(sk);
        }

        return err;
}

#if defined(OS_LINUX_KERNEL)
static unsigned int scaffold_poll(struct file *file, struct socket *sock, 
                                  poll_table *wait)
{
	struct sock *sk = sock->sk;
	unsigned int mask = 0;
	poll_wait(file, sk_sleep(sk), wait);
	mask = 0;

        if (sk->sk_state == SCAFFOLD_LISTEN) {
                struct scaffold_sock *ssk = scaffold_sk(sk);
                return list_empty(&ssk->accept_queue) ? 0 : (POLLIN | POLLRDNORM);
        }
	/* exceptional events? */
	if (sk->sk_err)
		mask |= POLLERR;
	if (sk->sk_shutdown == SHUTDOWN_MASK)
		mask |= POLLHUP;
	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= POLLRDHUP;

	/* readable? */
        if (sk->sk_type == SOCK_DGRAM || 
            sk->sk_type == SOCK_STREAM) {
                if (!skb_queue_empty(&sk->sk_receive_queue) ||
                    (sk->sk_shutdown & RCV_SHUTDOWN))
                        mask |= POLLIN | POLLRDNORM;
        }
        
	/* Connection-based need to check for termination and startup */
	if ((sk->sk_type == SOCK_STREAM || sk->sk_type == SOCK_DGRAM) && 
            sk->sk_state == SCAFFOLD_CLOSED)
		mask |= POLLHUP;

	if (sock_writeable(sk))
		mask |= POLLOUT | POLLWRNORM | POLLWRBAND;

	return mask;
}

static int scaffold_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sock *sk = sock->sk;
	int ret = 0;

        lock_sock(sk);
        
	switch (cmd) {
/*
		case SIOCSFMIGRATE:
                        if (sk->sk_state != SCAFFOLD_CONNECTED) {
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

static const struct proto_ops scaffold_ops = {
	.family =	PF_SCAFFOLD,
	.owner =	THIS_MODULE,
	.release =	scaffold_release,
	.bind =		scaffold_bind,
	.connect =	scaffold_connect,
	.accept =	scaffold_accept,
	.getname =	scaffold_getname,
	.listen =	scaffold_listen,
	.shutdown =	scaffold_shutdown,
	.sendmsg =	scaffold_sendmsg,
	.recvmsg =	scaffold_recvmsg,
#if defined(OS_LINUX_KERNEL)
	.setsockopt =	sock_no_setsockopt,
	.getsockopt =	sock_no_getsockopt,
	.socketpair =	sock_no_socketpair,
	.poll =	        scaffold_poll,
	.ioctl =	scaffold_ioctl,
	.mmap =		sock_no_mmap,
	.sendpage =	sock_no_sendpage,
#endif
};

static void scaffold_sock_destruct(struct sock *sk)
{
        __skb_queue_purge(&sk->sk_receive_queue);
	/* __skb_queue_purge(&sk->sk_error_queue); */

	if (sk->sk_type == SOCK_STREAM && sk->sk_state != SCAFFOLD_CLOSED) {
		LOG_ERR("Bad state %d %p\n",
                        sk->sk_state, sk);
		return;
	}

	if (!sock_flag(sk, SOCK_DEAD)) {
		LOG_DBG("Attempt to release alive scaffold socket: %p\n", sk);
		return;
	}

	if (atomic_read(&sk->sk_rmem_alloc)) {
                LOG_WARN("sk_rmem_alloc is not zero\n");
        }

	if (atomic_read(&sk->sk_wmem_alloc)) {
                LOG_WARN("sk_wmem_alloc is not zero\n");
        }

	atomic_dec(&scaffold_nr_socks);

	LOG_DBG("SCAFFOLD socket %p destroyed, %d are still alive.\n", 
               sk, atomic_read(&scaffold_nr_socks));
}

struct sock *scaffold_sk_alloc(struct net *net, struct socket *sock, 
                               gfp_t priority, int protocol, 
                               struct proto *prot)
{
        struct sock *sk;

        sk = sk_alloc(net, PF_SCAFFOLD, priority, prot);

	if (!sk)
		return NULL;

	sock_init_data(sock, sk);
        sk->sk_state = SCAFFOLD_CLOSED;
        sk->sk_family = PF_SCAFFOLD;
	sk->sk_protocol	= protocol;
	sk->sk_destruct	= scaffold_sock_destruct;
        sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;
        
        if (__scaffold_assign_sockid(sk) < 0) {
                LOG_DBG("could not assign sock id\n");
                sock_put(sk);
                return NULL;
        }
                
        LOG_DBG("SCAFFOLD socket %p created, %d are alive.\n", 
               sk, atomic_read(&scaffold_nr_socks) + 1);

        return sk;
}

/**
   Create a new Scaffold socket.
 */
static int scaffold_create(struct net *net, struct socket *sock, int protocol
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
                           , int kern
#endif
)
{
        struct sock *sk = NULL;
        int ret = 0;
        
        LOG_DBG("Creating SCAFFOLD socket\n");

        if (protocol && 
            (protocol != SCAFFOLD_PROTO_UDP && 
             protocol != SCAFFOLD_PROTO_TCP))
		return -EPROTONOSUPPORT;
        
	sock->state = SS_UNCONNECTED;
        
	switch (sock->type) {
                case SOCK_DGRAM:
                        if (!protocol)
                                protocol = SCAFFOLD_PROTO_UDP;
                        sock->ops = &scaffold_ops;
                        sk = scaffold_sk_alloc(net, sock, 
                                               GFP_KERNEL, 
                                               protocol,
                                               &scaffold_udp_proto);
                        break;
                case SOCK_STREAM: 
                        if (!protocol)
                                protocol = SCAFFOLD_PROTO_TCP;
                        sock->ops = &scaffold_ops;
                        sk = scaffold_sk_alloc(net, sock, 
                                               GFP_KERNEL, 
                                               protocol,
                                               &scaffold_tcp_proto);
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

        /* Initialize accept queue */
        INIT_LIST_HEAD(&scaffold_sk(sk)->accept_queue);
        INIT_LIST_HEAD(&scaffold_sk(sk)->syn_queue);
        
        if (sk->sk_prot->init) {
                /* Call protocol specific init */
                ret = sk->sk_prot->init(sk);
                
		if (ret < 0)
			sk_common_release(sk);
	}

        atomic_inc(&scaffold_nr_socks);
out:
        return ret;
}

static struct net_proto_family scaffold_family_ops = {
	.family = PF_SCAFFOLD,
	.create = scaffold_create,
	.owner	= THIS_MODULE,
};

int __init scaffold_init(void)
{
        int err = 0;

        err = service_init();

        if (err < 0) {
                LOG_CRIT("Cannot initialize service table\n");
                goto fail_service;
        }

        err = scaffold_sock_init();

        if (err < 0) {
                  LOG_CRIT("Cannot initialize scaffold sockets\n");
                  goto fail_sock;
        }
      
        err = packet_init();

        if (err != 0) {
		LOG_CRIT("Cannot init packet socket!\n");
		goto fail_packet;
	}

        err = proto_register(&scaffold_udp_proto, 1);

	if (err != 0) {
		LOG_CRIT("Cannot create scaffold_sock SLAB cache!\n");
		goto fail_proto;
	}
        
        err = sock_register(&scaffold_family_ops);

        if (err != 0) {
                LOG_CRIT("Cannot register socket family\n");
                goto fail_sock_register;
        }
out:
        return err;

	sock_unregister(PF_SCAFFOLD);
fail_sock_register:
	proto_unregister(&scaffold_udp_proto);     
fail_proto:
        packet_fini();
fail_packet:        
        scaffold_sock_fini();
fail_sock:
        service_fini();
fail_service:
        goto out;      
}

void __exit scaffold_fini(void)
{
     	sock_unregister(PF_SCAFFOLD);
	proto_unregister(&scaffold_udp_proto);
        packet_fini();
        scaffold_sock_fini();
        service_fini();
}
