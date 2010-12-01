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
#include <scaffold/atomic.h>
#include <scaffold/wait.h>
#include <scaffold/sock.h>
#include <scaffold/net.h>
#include <scaffold/skbuff.h>
#include <netinet/scaffold.h>
#include <scaffold_sock.h>
#include <scaffold_udp_sock.h>
#include <scaffold_tcp_sock.h>
#include <ctrl.h>

extern int __init packet_init(void);
extern void __exit packet_fini(void);

extern struct proto scaffold_udp_proto;
extern struct proto scaffold_tcp_proto;

static atomic_t scaffold_nr_socks = ATOMIC_INIT(0);
static atomic_t scaffold_sock_id = ATOMIC_INIT(1);

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
        scaffold_sock_set_state(sk, SF_UNBOUND);
        release_sock(sk);

        return 0;
}

int scaffold_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
        struct sock *sk = sock->sk;
        struct scaffold_sock *ssk = scaffold_sk(sk);
        struct sockaddr_sf *sfaddr = (struct sockaddr_sf *)addr;
        int ret = 0, cond = 1;
        
        if ((unsigned int)addr_len < sizeof(struct sockaddr_sf))
                return -EINVAL;
        else if (addr_len % sizeof(struct sockaddr_sf) != 0)
                return -EINVAL;
        
        /* Call the protocol's own bind, if it exists */
	if (sk->sk_prot->bind)
		return sk->sk_prot->bind(sk, addr, addr_len);

        lock_sock(sk);

        LOG_DBG("handling bind\n");

        if (scaffold_sock_flag(ssk, SCAFFOLD_FLAG_HOST_CTRL_MODE)) {
                ret = 1;
                scaffold_sock_set_state(sk, SF_BOUND);
        } else {
                struct ctrlmsg_register cm;
                cm.cmh.type = CTRLMSG_TYPE_REGISTER;
                cm.cmh.len = sizeof(cm);
                memcpy(&cm.srvid, &sfaddr->sf_srvid, sizeof(sfaddr->sf_srvid));
                ret = ctrl_sendmsg(&cm.cmh, GFP_KERNEL);
        }
        if (ret < 0) {
                LOG_ERR("bind failed\n");
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
                LOG_DBG("socket in controller mode\n");
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
                }
        } else {
                release_sock(sk);
        }
        return ret;
}


static int scaffold_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
        int err = -EINVAL;
        
        if (sock->type != SOCK_DGRAM && sock->type != SOCK_STREAM)
		return -EOPNOTSUPP;		
	
        lock_sock(sk);

        LOG_DBG("listening on socket\n");

	if (sk->sk_state == SF_UNBOUND) {
                sk->sk_max_ack_backlog = backlog;               
//                retval = sfnet_handle_listen_socket(sk, backlog);
	}

        release_sock(sk);

        return err;
}

struct sock *scaffold_accept_dequeue(struct sock *parent, 
                                     struct socket *newsock)
{
	struct sock *sk = NULL;

        /* Parent sock is already locked... */
        while (1) {
                //struct socket_id sockid;

                if (0 /*sfnet_accept_dequeue(parent, &sockid) != 1 */)
                        break;
                
                switch (newsock->type) {
                case SOCK_DGRAM:
                        //newsock->ops = &scaffold_dgram_ops;
                        sk = scaffold_sk_alloc(parent->sk_net, newsock, 
                                               GFP_KERNEL, 
                                               parent->sk_protocol,
                                               &scaffold_udp_proto);
                        break;
                case SOCK_STREAM: 
                        //newsock->ops = &scaffold_stream_ops;
                        sk = scaffold_sk_alloc(parent->sk_net, newsock, 
                                               GFP_KERNEL,
                                               parent->sk_protocol,
                                               &scaffold_tcp_proto);
                        break;
                case SOCK_SEQPACKET:	
                case SOCK_RAW:
                default:
                        return NULL;
                }
                
                if (!sk)
                        break;

                // Inherit the service id from the parent socket
                memcpy(&scaffold_sk(sk)->local_srvid, 
                       &scaffold_sk(parent)->local_srvid, 
                       sizeof(struct sockaddr_sf));
                
                scaffold_sk(sk)->tot_bytes_sent = 0;

                lock_sock(sk);

                if (0 /* sfnet_assign_sock(sk, sockid) != 0 */) {
                        release_sock(sk);
                        sk_free(sk);
                        sk = NULL;
                        break;
                }

                if (sk->sk_state == SF_CLOSED) {
			release_sock(sk);
			continue;
		}
               
		if (1 /*sk->sk_state == SF_BOUND || !newsock */) {

			if (newsock)
				sock_graft(sk, newsock);
                        
                        atomic_inc(&scaffold_nr_socks);

			release_sock(sk);

			return sk;
		} 
                /* Should not happen. */
                release_sock(sk);
                sk_free(sk);
                sk = NULL;
        }

	return NULL;
}

static int scaffold_accept(struct socket *sock, struct socket *newsock, 
                           int flags)
{
	DECLARE_WAITQUEUE(wait, current);
	struct sock *sk = sock->sk, *nsk;
	long timeo;
	int err = 0;

	lock_sock(sk);

	if (sk->sk_state != SF_LISTEN) {
		err = -EBADFD;
		goto done;
	}

	timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);

	/* Wait for an incoming connection. (wake-one). */
	add_wait_queue_exclusive(sk_sleep(sk), &wait);

	while (!(nsk = scaffold_accept_dequeue(sk, newsock))) {
		
                set_current_state(TASK_INTERRUPTIBLE);
		
                if (!timeo) {
			err = -EAGAIN;
			break;
		}

		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);

                if (sk->sk_state != SF_LISTEN) {
                        err = -EBADFD;
                        break;
                }

		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			break;
		}
	}
        
	set_current_state(TASK_RUNNING);
	remove_wait_queue(sk_sleep(sk), &wait);

	if (err)
		goto done;

	newsock->state = SS_CONNECTED;
        
done:
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
        int ret = 0, connect_ret = 1;
        int nonblock = flags & O_NONBLOCK;

        if (addr->sa_family != AF_SCAFFOLD)
                return -EAFNOSUPPORT;
        
        lock_sock(sk);
        
        if (sk->sk_state == SF_BOUND) {
                release_sock(sk);
                return -EISCONN;
        }

        if (sk->sk_state >= SF_REQUEST) {
                release_sock(sk);
                return -EINPROGRESS;
        }
        
        if (sk->sk_state != SF_UNBOUND && 
            sk->sk_state != SF_NEW) {
                release_sock(sk);
                return -EINVAL;
        }

        /* Set the peer address */
        memcpy(&scaffold_sk(sk)->peer_srvid, &sfaddr->sf_srvid, 
               sizeof(struct service_id));

        if (0 /* sfnet_handle_connect_socket(sk, &sfaddr->sf_oid, 
                 sfaddr->sf_flags, &connect_ret) != 0 */) {
                release_sock(sk);
                LOG_ERR("connect() failed, connect_ret=%d\n", connect_ret);
                return ret;
        }        

        LOG_DBG("waiting for connect\n");

        if (nonblock) {
                if (ret == 0)
                        ret = -EINPROGRESS;
        } else {
                /* Go to sleep, wait for timeout or successful connection */
                release_sock(sk);
                ret = wait_event_interruptible(*sk_sleep(sk), 
                                                       connect_ret != 1);
                lock_sock(sk);

                /* Check if we were interrupted */
                if (ret == 0) {
                        if (connect_ret == 0) {
                                LOG_DBG("connect returned, connect_ret=%d\n", connect_ret);
                                
                                if (connect_ret == 0) {
                                        sock->state = SS_CONNECTED;
                                }
                        } else {
                                LOG_ERR("connect() wait for BOUND failed, connect_ret=%d\n", connect_ret);
                                ret = connect_ret;
                        }
                }
        }

        release_sock(sk);
                
        return ret;
}
static int scaffold_sendmsg(struct kiocb *iocb, struct socket *sock, 
                            struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;

	/* We may need to bind the socket. */
	if (sk->sk_state == SF_NEW && scaffold_autobind(sk) < 0)
		return -EAGAIN;

	return sk->sk_prot->sendmsg(iocb, sk, msg, size);
}

static int scaffold_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
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
	case SF_CLOSED:
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
	case SF_LISTEN:
		if (!(how & RCV_SHUTDOWN))
			break;
		/* Fall through */
	case SF_REQUEST:
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
                sk->sk_prot->close(sk, timeout);
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

        if (sk->sk_state == SF_LISTEN) {
                //return !sfnet_accept_queue_empty(sk) ? (POLLIN | POLLRDNORM) : 0;

                return 0;
        }
	/* exceptional events? */
	if (sk->sk_err)
		mask |= POLLERR;
	if (sk->sk_shutdown == SHUTDOWN_MASK)
		mask |= POLLHUP;
	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= POLLRDHUP;

	/* readable? */
        if (sk->sk_type == SOCK_STREAM) {
/*
                if (sfnet_tcp_bufcnt(sk, 1, 1) > 0 ||
                    (sk->sk_shutdown & RCV_SHUTDOWN))
                        mask |= POLLIN | POLLRDNORM;
*/
        } else if (sk->sk_type == SOCK_DGRAM) {
                if (!skb_queue_empty(&sk->sk_receive_queue) ||
                    (sk->sk_shutdown & RCV_SHUTDOWN))
                        mask |= POLLIN | POLLRDNORM;
        }

	/* Connection-based need to check for termination and startup */
	if ((sk->sk_type == SOCK_STREAM || sk->sk_type == SOCK_DGRAM) && 
            sk->sk_state == SF_CLOSED)
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
                        if (sk->sk_state != SF_BOUND) {
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

/* 
   Below are mappings of generic datagram operations. These functions
   should typically override, or call, protocol specific functions
   (defined in struct proto), e.g., for UDP and TCP. This allows
   better code reuse and the ability to override functions that
   require protocol specific implementations.

   However, currently the above functionality is not really used by
   SCAFFOLD. This is primarily because UDP and TCP protocols in
   SCAFFOLD are very similar (both connection oriented).

   In the future, SCAFFOLD sockets should be structured more like the
   inet family type. See, for example, the relationship between the
   inet_sock family type and protocol specific implementations, like
   UDP and TCP, in the Linux source code.

 */
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

	if (sk->sk_type == SOCK_STREAM && sk->sk_state != SF_CLOSED) {
		LOG_ERR("Attempt to release Scaffold TCP socket in state %d %p\n",
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

struct sock *scaffold_sk_alloc(struct net *net, struct socket *sock, gfp_t priority,
                               int protocol, struct proto *prot)
{
        struct sock *sk;

        sk = sk_alloc(net, PF_SCAFFOLD, priority, prot);

	if (!sk)
		return NULL;

	sock_init_data(sock, sk);
        
        sk->sk_family = PF_SCAFFOLD;
	sk->sk_protocol	= protocol;
	sk->sk_destruct	= scaffold_sock_destruct;
        sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;
        
        /* TODO: do not use host controller mode by default */
        //scaffold_sock_set_flag(scaffold_sk(sk), SCAFFOLD_FLAG_HOST_CTRL_MODE);

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

        if (protocol && (protocol != SF_PROTO_UDP && protocol != SF_PROTO_TCP))
		return -EPROTONOSUPPORT;
        
	sock->state = SS_UNCONNECTED;
        
	switch (sock->type) {
                case SOCK_DGRAM:
                        if (!protocol) 
                                protocol = SF_PROTO_UDP;
                        sock->ops = &scaffold_ops;
                        sk = scaffold_sk_alloc(net, sock, 
                                               GFP_KERNEL, 
                                               protocol,
                                               &scaffold_udp_proto);
                        break;
                case SOCK_STREAM: 
                        if (!protocol)
                                protocol = SF_PROTO_TCP;
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

        /* Add to protocol hash chains. */
        sk->sk_prot->hash(sk);
        
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
        goto out;      
}

void __exit scaffold_fini(void)
{
     	sock_unregister(PF_SCAFFOLD);
	proto_unregister(&scaffold_udp_proto);
        packet_fini();
        scaffold_sock_fini();
}
