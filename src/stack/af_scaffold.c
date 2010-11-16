/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

#if defined(__KERNEL__)
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/kthread.h>
#include <linux/string.h>
#include <linux/udp.h>
#include <linux/proc_fs.h>
#include <net/protocol.h>
#include "linux/scaffold_netlink.h"

#define FREE_SKB(skb) kfree_skb(skb)

MODULE_AUTHOR("Erik Nordstroem");
MODULE_DESCRIPTION("Scaffold socket API for Linux");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

#define RTO_INITIAL_DISABLED 0 // Use whatever value is set by default
static uint rto = RTO_INITIAL_DISABLED;
static int rto_dynamic = 0;
static uint tx_burst = 0;

module_param(rto, uint, 0);
MODULE_PARM_DESC(rto, "Set initial RTO value (micro seconds).");

module_param(rto_dynamic, int, 0);
MODULE_PARM_DESC(rto_dynamic, "Enable dynamic RTO using Van Jacobson's algorithm.");

module_param(tx_burst, uint, 0);
MODULE_PARM_DESC(tx_burst, "Maximum packets the transmit task sends in one burst (0 = use default value).");

#if defined(ENABLE_DEBUG)
static uint debug = 0;
module_param(debug, uint, 0);
MODULE_PARM_DESC(debug, "Set debug level 0-5 (0=off).");
#endif

#else /* USERLEVEL */
#include <userlevel/wait.h>
#include <userlevel/sock.h>
#include <userlevel/net.h>
#include <userlevel/skbuff.h>

#endif /* __KERNEL__ */

/* Common includes */
#include <scaffold_sock.h>
#include <scaffold_udp_sock.h>
#include <scaffold_tcp_sock.h>
#include <scaffold/debug.h>
#include <scaffold/atomic.h>
#include <netinet/scaffold.h>

static atomic_t scaffold_nr_socks = ATOMIC_INIT(0);
static struct sock *scaffold_sk_alloc(struct net *net, struct socket *sock, 
                                      gfp_t priority, struct proto *prot);

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

int scaffold_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
        struct sock *sk = sock->sk;
        struct sockaddr_sf *sfaddr = (struct sockaddr_sf *)addr;
        int ret = 0, cond = 1;
        
        if (addr_len < sizeof(struct sockaddr_sf))
                return -EINVAL;
        else if (addr_len % sizeof(struct sockaddr_sf) != 0)
                return -EINVAL;
        
        lock_sock(sk);

//        ret = sfnet_handle_bind_socket(sk, &sfaddr->ssf_sid, &cond);

        if (ret < 0) {
                LOG_ERR("af_scaffold: bind failed\n");
                release_sock(sk);
                return ret;
        }

        memcpy(&scaffold_sk(sk)->local_sid, &sfaddr->ssf_sid, sizeof(struct service_id));

        /* 
           Return value of 1 indicates we are in controller mode -->
           do not wait for a reply 
        */
        if (ret == 1) {
                LOG_DBG("af_scaffold: bind in controller mode\n");
                release_sock(sk);
                ret = 0;
        } else if (ret == 0) {
                release_sock(sk);
                /* Sleep and wait response or timeout */
                ret = wait_event_interruptible(*sk_sleep(sk), cond != 1);

                if (ret != 0) {
                        LOG_ERR("af_scaffold: bind interrupted\n");
                } else {
                        ret = cond;
                        LOG_ERR("af_scaffold: bind returned %d\n", ret);
                }
        } else {
                release_sock(sk);
        }

        return ret;
}

static int scaffold_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
        int retval = EINVAL;
        
        if (sock->type != SOCK_DGRAM && sock->type != SOCK_STREAM)
		return -EOPNOTSUPP;		
	
        lock_sock(sk);

	if (sk->sk_state == SF_UNBOUND) {
                sk->sk_max_ack_backlog = backlog;               
//                retval = sfnet_handle_listen_socket(sk, backlog);
	}

        release_sock(sk);

        return -retval;
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

	sa->ssf_family  = AF_SCAFFOLD;

	if (peer)
		memcpy(&sa->ssf_sid, &scaffold_sk(sk)->peer_sid, 
                       sizeof(struct sockaddr_sf));
	else
		memcpy(&sa->ssf_sid, &scaffold_sk(sk)->local_sid, 
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
        memcpy(&scaffold_sk(sk)->peer_sid, &sfaddr->ssf_sid, sizeof(struct service_id));

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
                ret = wait_event_interruptible(*sk_sleep(sk), connect_ret != 1);
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

static int scaffold_sendmsg(struct kiocb *kiocb, struct socket *sock,
                            struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
        int ret = -ENOMEM;
        struct service_id dst_sid;
        /* Check if we are calling send() or sendto(), i.e., whether
           we are given the destination service id or not. */
        if (msg->msg_name) {
                struct sockaddr_sf *sfaddr = msg->msg_name;
                
                if (sfaddr->ssf_family != AF_SCAFFOLD)
                        return -EAFNOSUPPORT;
                
                memcpy(&dst_sid, &sfaddr->ssf_sid, sizeof(struct service_id)); 
        } else {
                memcpy(&dst_sid, &scaffold_sk(sk)->peer_sid, sizeof(struct service_id));
        }
        
        //LOG_DBG("sendmsg() to serviceId=%u\n", ntohs(dst_oid.s_oid));
               
        lock_sock(sk);
        
        if (sk->sk_state == SF_RECONNECT) {
                release_sock(sk);
                
                LOG_DBG("af_scaffold: in RECONNECT. Waiting...\n");

                ret = wait_event_interruptible(*sk_sleep(sk), sk->sk_state != SF_RECONNECT);
                
                /* Check if we were interrupted */
                if (ret != 0) {
                        LOG_DBG("Interrupted while waiting in RECONNECT\n");
                        return ret;
                }

                lock_sock(sk);
                
                if (sk->sk_state != SF_BOUND)  {
                        release_sock(sk);
                        return -ENOTCONN;
                }
        }

        //ret = sfnet_handle_send_socket(sk, &dst_oid, msg->msg_iov, len, msg->msg_flags & MSG_DONTWAIT);

        if (ret == 0) {
                if (msg->msg_flags & MSG_DONTWAIT) {
                        //LOG_DBG("send(): MSG_DONTWAIT set, returning -EWOULDBLOCK\n");
                        ret = -EWOULDBLOCK;
                } else {
                        release_sock(sk);

                        ret = wait_event_interruptible(*sk_sleep(sk), (atomic_read(&sk->sk_wmem_alloc) << 1) < sk->sk_sndbuf);
                        
                        if (ret != 0) {
                                LOG_DBG("wait for write memory interrupted\n");
                                return ret;
                        }

                        lock_sock(sk);

                        ret = len;
                }
        } else if (ret < 0) {
                LOG_DBG("%s send_socket returned error %d\n", 
                        __FUNCTION__, ret);
        }

        if (ret > 0) {
                scaffold_sk(sk)->tot_bytes_sent += len;
        }
        release_sock(sk);

        return ret;
}

static int scaffold_dgram_recvmsg(struct kiocb *iocb, struct socket *sock,
                               struct msghdr *msg, size_t len, int flags)
{
	struct sock *sk = sock->sk;
	struct scaffold_sock *ss = scaffold_sk(sk);
        struct sockaddr_sf *sfaddr = (struct sockaddr_sf *)msg->msg_name;
        int retval = -ENOMEM;
	long timeo;
        
        lock_sock(sk);
        
        if (sk->sk_state != SF_UNBOUND && 
            sk->sk_state != SF_BOUND && 
            sk->sk_state != SF_CLOSED) {
                /* SF_CLOSED is a valid state here because recvmsg
                 * should return 0 and not an error */
		retval = -ENOTCONN;
		goto out;
	}

        if (msg->msg_namelen < sizeof(struct sockaddr_sf)) {
                retval = -EINVAL;
                LOG_DBG("address length is incorrect\n");
                goto out;
        }

	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);

	do {
		struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);

		if (skb)
			goto found_ok_skb;
	
		if (sk->sk_state >= SF_CLOSED) {
                        /*
			if (!sock_flag(sk, SOCK_DONE)) {
				retval = -ENOTCONN;
				break;
			}
                        */
                        retval = 0;
			break;
		}
                
		if (!timeo) {
			retval = -EAGAIN;
			break;
		}

		if (signal_pending(current)) {
			retval = sock_intr_errno(timeo);
			break;
		}
                //LOG_DBG("waiting for data\n");

		sk_wait_data(sk, &timeo);
		continue;
	found_ok_skb:
		if (len >= skb->len) {
			retval = skb->len;
                        len = skb->len;
                } else if (len < skb->len) {
			msg->msg_flags |= MSG_TRUNC;
                        retval = len;
                }
                
                /* Copy service id */
                if (sfaddr) {
                        size_t addrlen = msg->msg_namelen;
                        unsigned short from = udp_hdr(skb)->source;

                        sfaddr->ssf_family = AF_SCAFFOLD;
                        msg->msg_namelen = sizeof(struct sockaddr_sf);
                        memcpy(&sfaddr->ssf_sid, &from, sizeof(struct service_id));

                        /* Copy also our local service id to the
                         * address buffer if size admits */
                        if (addrlen >= sizeof(struct sockaddr_sf) * 2) {
                                sfaddr = (struct sockaddr_sf *)(msg->msg_name + sizeof(struct sockaddr_sf));
                                sfaddr->ssf_family = AF_SCAFFOLD;

                                memcpy(&sfaddr->ssf_sid, &ss->local_sid, 
                                       sizeof(struct service_id));
                        }
                }
                
                //LOG_DBG("dequeing skb with length %u len=%zu retval=%d\n", skb->len, len, retval);

		if (skb_copy_datagram_iovec(skb, 0, msg->msg_iov, len)) {
			/* Exception. Bailout! */
			retval = -EFAULT;
                        LOG_DBG("could not copy data, len=%zu\n", len);
			break;
		}
		if (!(flags & MSG_PEEK))
			sk_eat_skb(sk, skb, 0);
		break;
	} while (1);
out:
        release_sock(sk);
        
        return retval;
}

static int scaffold_sock_is_valid_conn_state(int state)
{
        return (state == SF_BOUND ||
                state == TCP_FINWAIT1 ||
                state == TCP_FINWAIT2 ||
                state == TCP_SIMCLOSE ||
                state == TCP_LASTACK ||
                state == TCP_CLOSEWAIT);
}

static int scaffold_stream_recvmsg(struct kiocb *iocb, struct socket *sock,
                                   struct msghdr *msg, size_t len, int flags)
{
	struct sock *sk = sock->sk;
        struct sockaddr_sf *sfaddr = (struct sockaddr_sf *)msg->msg_name;
        int retval = -ENOMEM;
	long timeo;
        static size_t tot_bytes_read = 0;

        lock_sock(sk);
       
        if (msg->msg_namelen < sizeof(struct sockaddr_sf)) {
                retval = -EINVAL;
                LOG_DBG("address length is incorrect\n");
                goto out;
        }

	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
        
	do {
                int datalen = 0;

                if (!scaffold_sock_is_valid_conn_state(sk->sk_state)) {
                        if (sk->sk_state == SF_RECONNECT) {
                                LOG_DBG("af_scaffold: in RECONNECT. Waiting...\n");
                                
                                if (msg->msg_flags & MSG_DONTWAIT) {
                                        //LOG_DBG("send(): MSG_DONTWAIT set, returning -EWOULDBLOCK\n");
                                        release_sock(sk);
                                        return -EWOULDBLOCK;
                                }            
                                
                                release_sock(sk);

                                retval = wait_event_interruptible(*sk_sleep(sk), atomic_read(&sk->sk_wmem_alloc) < sk->sk_sndbuf);

                                /* Check if we were interrupted */
                                if (retval != 0) {
                                        LOG_DBG("Interrupted while waiting in RECONNECT\n");
                                        return retval;
                                } 

                                lock_sock(sk);

                                if (sk->sk_state != SF_BOUND)  {
                                        retval = -ENOTCONN;
                                        break;
                                }
                        } else {
                                retval = -ENOTCONN;
                                break;
                        }
                }

//                datalen = sfnet_tcp_bufcnt(sk, 1, 1);
               
                if (datalen == -1) {
                        retval = -EINVAL;
                        break;
                }

                if (datalen == 0 && sock_flag(sk, SOCK_DONE)) {
                        /* SOCK_DONE means FIN received, and should be
                         * in buffer. We can then safely assume that
                         * reading 0 from buffer indicates there is no
                         * more data in the stream. */ 
                        LOG_DBG("%s: SOCK_DONE set, tot_bytes_read=%zu\n", 
                                __FUNCTION__, tot_bytes_read);
                        retval = 0;
                        break;
                }

		if (datalen > 0)
			goto found_data;
	              
		if (!timeo) {
			retval = -EAGAIN;
			break;
		}

		if (signal_pending(current)) {
			retval = sock_intr_errno(timeo);
			break;
		}
                //printk("waiting for data\n");

		sk_wait_data(sk, &timeo);
		continue;
	found_data:
		if (len > datalen) {
                        len = datalen;
                }
                
                /* Copy service ids */
                if (sfaddr) {
                        size_t addrlen = msg->msg_namelen;
                        
                        sfaddr->ssf_family = AF_SCAFFOLD;
                        msg->msg_namelen = sizeof(struct sockaddr_sf);
                        memcpy(&sfaddr->ssf_sid, &scaffold_sk(sk)->peer_sid, sizeof(struct service_id));

                        /* Copy also our local service id to the
                         * address buffer if size admits */
                        if (addrlen >= sizeof(struct sockaddr_sf) * 2) {
                                sfaddr = (struct sockaddr_sf *)(msg->msg_name + sizeof(struct sockaddr_sf));
                                sfaddr->ssf_family = AF_SCAFFOLD;

                                memcpy(&sfaddr->ssf_sid, &scaffold_sk(sk)->local_sid, 
                                       sizeof(struct service_id));
                        }
                }

//                retval = sfnet_handle_recv_socket(sk, msg->msg_iov, len, flags);

                if (retval < 0) {
                        /* Exception. Bailout! */
                        LOG_DBG("could not copy data, len=%zu\n", len);
			break;
		} else if (retval == 0) {
                        LOG_DBG("%s: retval is 0 after recv_socket\n", __FUNCTION__);
                }
                tot_bytes_read += len;
		break;
	} while (1);
out:
        release_sock(sk);

        return retval;
}

static int scaffold_shutdown(struct socket *sock, int mode)
{
	struct sock *sk = sock->sk;
	int err = 0;

	if (!sk) 
                return 0;

	lock_sock(sk);

	if (!sk->sk_shutdown) {
		sk->sk_shutdown = SHUTDOWN_MASK;
//                sfnet_handle_release_socket(sk);

		if (sock_flag(sk, SOCK_LINGER) && sk->sk_lingertime)
			err = scaffold_wait_state(sk, SF_CLOSED, sk->sk_lingertime);
	}

	release_sock(sk);

        return 0;
}

int scaffold_release(struct socket *sock)
{
        int err = 0;
        struct sock *sk = sock->sk;
    	struct sk_buff *skb;

        /* Apparently the socket can be NULL, for example, if close()
         * is called on an invalid file descriptor. */
	if (!sk)
		return 0;
        
        scaffold_shutdown(sock, 2);

	sock_orphan(sk);

        // This is done in destruct too?
        while ((skb = skb_dequeue(&sk->sk_receive_queue)) != NULL) {
                FREE_SKB(skb);
	}

        LOG_DBG("SCAFFOLD socket %p released, refcount=%d, tot_bytes_sent=%lu\n", 
               sk, atomic_read(&sk->sk_refcnt) - 1, scaffold_sk(sk)->tot_bytes_sent);
        
	sock_put(sk);
    
        return err;
}

#if defined(__KERNEL__)
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

static int scaffold_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	//struct scaffold_sock *scaff = scaffold_sk(sk);
	int rc;

        LOG_DBG("%s: received data\n", __FUNCTION__);

        // Queue skbs on socket for reading via recv() or recvmsg()
        if ((rc = sock_queue_rcv_skb(sk,skb)) < 0) {
		/* Note that an ENOMEM error is charged twice */
		if (rc == -ENOMEM) {
			// increase stats
                }
		goto drop;
	}
        LOG_DBG("%s: skb queued\n", __FUNCTION__);
 
        return 0;
drop:
        LOG_DBG("%s: skb queue error!\n", __FUNCTION__);

        FREE_SKB(skb);

        return -1;
}

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
static const struct proto_ops scaffold_dgram_ops = {
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
	.recvmsg =	scaffold_dgram_recvmsg,
#if defined(__KERNEL__)
	.setsockopt =	sock_no_setsockopt,
	.getsockopt =	sock_no_getsockopt,
	.socketpair =	sock_no_socketpair,
	.poll =	        scaffold_poll,
	.ioctl =	scaffold_ioctl,
	.mmap =		sock_no_mmap,
	.sendpage =	sock_no_sendpage,
#endif
};

/* 
   These are generic stream operations, may be overriden by 
   struct proto functions 
*/
static const struct proto_ops scaffold_stream_ops = {
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
	.recvmsg =	scaffold_stream_recvmsg,
#if defined(__KERNEL__)
	.setsockopt =	sock_no_setsockopt,
	.getsockopt =	sock_no_getsockopt,
	.socketpair =	sock_no_socketpair,
	.poll =	        scaffold_poll,
	.ioctl =	scaffold_ioctl,
	.mmap =		sock_no_mmap,
	.sendpage =	sock_no_sendpage,
#endif
};

/* 
   Specific protocol operations. They override generic 
   datagram and stream operations above.
*/
static struct proto scaffold_udp_proto = {
	.name			= "SCAFFOLD_UDP",
	.owner			= THIS_MODULE,
	.obj_size		= sizeof(struct scaffold_udp_sock),
	.backlog_rcv            = scaffold_queue_rcv_skb,
};

static struct proto scaffold_tcp_proto = {
	.name			= "SCAFFOLD_TCP",
	.owner			= THIS_MODULE,
	.obj_size		= sizeof(struct scaffold_tcp_sock),
	.backlog_rcv            = scaffold_queue_rcv_skb,
};


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
                                               &scaffold_udp_proto);
                        break;
                case SOCK_STREAM: 
                        //newsock->ops = &scaffold_stream_ops;
                        sk = scaffold_sk_alloc(parent->sk_net, newsock, 
                                               GFP_KERNEL, 
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
                memcpy(&scaffold_sk(sk)->local_sid, 
                       &scaffold_sk(parent)->local_sid, 
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
                /*
                  FIXME: It seems as, if sometimes, a socket in
                  Scaffold has already gone from BOUND to some other
                  state before the application has had a chance to
                  accept it. In that case, should we simply delete the
                  socket, or let the application deal with the
                  non-BOUND state once accepted?

                  I think the safest thing to do is to let the
                  application deal with it, because
                  sfnet_assign_socket() has already associated the
                  C-sock with a Scaffold data type. If we delete the
                  C-socket here, the Scaffold C++ version of the
                  socket will have a bad handle.

                  If we want to delete the socket here, we must first
                  assure that sfnet_assign_sock() does not associate
                  the C-sock with the C++ SFSock, and then make it return
                  an error so that we know the assignment was not made.

                  For now, accept the socket no matter what state it
                  is in.
                 */
		if (1 /*sk->sk_state == SF_BOUND || !newsock */) {

			if (newsock)
				sock_graft(sk, newsock);
                        
                        atomic_inc(&scaffold_nr_socks);

			release_sock(sk);

#if defined(__KERNEL__)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
                        local_bh_disable();
                        sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
                        local_bh_enable();
#endif
#endif
			return sk;
		} 
                /* Should not happen. */
                release_sock(sk);
                sk_free(sk);
                sk = NULL;
        }

	return NULL;
}

static void scaffold_sock_destruct(struct sock *sk)
{
	skb_queue_purge(&sk->sk_receive_queue);

	if (!sock_flag(sk, SOCK_DEAD)) {
		LOG_DBG("Attempt to release alive scaffold socket: %p\n", sk);
		return;
	}

	atomic_dec(&scaffold_nr_socks);

#if defined(__KERNEL__)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
	local_bh_disable();
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	local_bh_enable();
#endif
#endif
	LOG_DBG("SCAFFOLD socket %p destroyed, %d are still alive.\n", 
               sk, atomic_read(&scaffold_nr_socks));
}

struct sock *scaffold_sk_alloc(struct net *net, struct socket *sock, gfp_t priority, 
                               struct proto *prot)
{
        struct sock *sk;

        sk = sk_alloc(net, PF_SCAFFOLD, priority, prot);

	if (!sk)
		return NULL;

	sock_init_data(sock, sk);
        
        sk->sk_family = PF_SCAFFOLD;
	sk->sk_protocol	= PF_SCAFFOLD;
	sk->sk_destruct	= scaffold_sock_destruct;
        //scaffold_sk(sk)->sfsock = NULL;
        
        LOG_DBG("SCAFFOLD socket %p created, %d are alive.\n", 
               sk, atomic_read(&scaffold_nr_socks) + 1);

        return sk;
}

/**
   Create a new Scaffold socket.
 */
static int scaffold_create(struct net *net, struct socket *sock, int protocol, int kern)
{
        struct sock *sk;
        int ret = 0;
        uint16_t proto;
        
        if (protocol && (protocol != SF_PROTO_UDP && protocol != SF_PROTO_TCP))
		return -EPROTONOSUPPORT;
        
	sock->state = SS_UNCONNECTED;
        
	switch (sock->type) {
                case SOCK_DGRAM:
                        proto = SF_PROTO_UDP;
                        sock->ops = &scaffold_dgram_ops;
                        sk = scaffold_sk_alloc(net, sock, 
                                               GFP_KERNEL, 
                                               &scaffold_udp_proto);
                        break;
                case SOCK_STREAM: 
                        proto = SF_PROTO_TCP;
                        sock->ops = &scaffold_stream_ops;
                        sk = scaffold_sk_alloc(net, sock, 
                                               GFP_KERNEL, 
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

        atomic_inc(&scaffold_nr_socks);

        //scaffold_insert_socket(scaffold_sockets_unbound, sk);
//        ret = sfnet_handle_new_socket(sk, proto);

        if (ret < 0) {
                sk_free(sk);
                sk = NULL;
        }
out:
        if (!sk) {
                atomic_dec(&scaffold_nr_socks);
                ret = -ENOMEM;
        } else {
#if defined(__KERNEL__)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
		local_bh_disable();
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
		local_bh_enable();
#endif
#endif
	}
        return ret;
}
/*
static int scaffold_eth_rcv(struct sk_buff *skb, struct net_device *dev,
                            struct packet_type *pt, struct net_device *orig_dev)
{        
        return sfnet_scaffold_rcv(skb);
}

static int scaffold_ip_rcv(struct sk_buff *skb)
{
        return sfnet_scaffold_rcv(skb);
}

static void scaffold_ip_err(struct sk_buff *skb, u32 info)
{
        FREE_SKB(skb);
}
*/

static struct net_proto_family scaffold_family_ops = {
	.family = PF_SCAFFOLD,
	.create = scaffold_create,
	.owner	= THIS_MODULE,
};

EXPORT_SYMBOL(scaffold_getname);

/* Scaffold packet type for Scaffold over Ethernet */
/*
static struct packet_type scaffold_packet_type = {
        .type = __constant_htons(ETH_P_SCAFFOLD),
        .func = scaffold_eth_rcv,
};
*/
/* Scaffold protocol type for Scaffold over IP */
/*
static struct net_protocol scaffold_protocol = {
	.handler =	scaffold_ip_rcv,
	.err_handler =	scaffold_ip_err,
	.no_policy =	1,
};
*/
#if defined(__KERNEL__)
static int scaffold_netdev_event(struct notifier_block *this,
                                 unsigned long event, void *ptr)
{
	struct net_device *dev = (struct net_device *)ptr;

        if (dev->nd_net != &init_net)
                return NOTIFY_DONE;
        
	switch (event) {
	case NETDEV_UP:
		LOG_DBG("Netdev UP %s\n", dev->name);
//                sfnet_handle_link_event(dev->name, 1);
		break;
	case NETDEV_GOING_DOWN:
		LOG_DBG("Netdev GOING_DOWN %s\n", dev->name);
                //              sfnet_handle_link_event(dev->name, 0);
                break;
	case NETDEV_DOWN:
                LOG_DBG("Netdev DOWN\n");
		//LOG_DBG("Netdev DOWN %s\n", dev->name);
                break;
	default:
		break;
	};

	return NOTIFY_DONE;
}

static struct notifier_block netdev_notifier = {
      notifier_call:scaffold_netdev_event,
};
#endif /* __KERNEL__ */

/*
static int scaffold_inetaddr_event(struct notifier_block *this,
				  unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	struct in_device *indev;

	if (!ifa)
		return NOTIFY_DONE;

	indev = ifa->ifa_dev;

	if (!indev)
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:
		LOG_DBG("inetdev UP\n");
		break;
	case NETDEV_DOWN:
		LOG_DBG("inetdev DOWN\n");
                break;
	default:
		break;
	};
	return NOTIFY_DONE;
}
*/

/* Notifier for inetaddr addition/deletion events.  */
/*
static struct notifier_block inetaddr_notifier = {
	.notifier_call = scaffold_inetaddr_event,
};
*/

int __init scaffold_init(void)
{
        int err = 0;

        LOG_DBG("Loaded scaffold protocol module\n");
        /*
        if (inet_add_protocol(&scaffold_protocol, IPPROTO_SCAFFOLD) < 0) {
                LOG_CRIT("%s: Cannot register Scaffold IP protocol\n", __func__);
                goto out_scaffold_protocol_failure;
        }
        
        */

#if defined(__KERNEL__)
	err = register_netdevice_notifier(&netdev_notifier);

	if (err < 0) {
                LOG_CRIT("%s: Cannot register netdevice notifier\n", __func__);
                goto fail_netdev_notifier;
        }
        err = scaffold_netlink_init();
        
	if (err < 0) {
                LOG_CRIT("%s: Cannot create netlink socket\n", __func__);
                goto fail_netlink;
        }
#endif

        err = proto_register(&scaffold_udp_proto, 1);

	if (err != 0) {
		LOG_CRIT("%s: Cannot create scaffold_sock SLAB cache!\n",
		       __func__);
		goto fail_proto;
	}
        
        err = sock_register(&scaffold_family_ops);

        if (err != 0) {
                LOG_CRIT("%s: Cannot register socket family\n", 
                       __func__);
                goto fail_sock_register;
        }
        /*   
	err = register_inetaddr_notifier(&inetaddr_notifier);
        
        if (err < 0) {
                LOG_CRIT("%s: Cannot register inetaddr notifier\n", __func__);
                goto out_scaffold_inetaddr_notifier_failure;
        }
        */
        /* dev_add_pack(&scaffold_packet_type); */

/*
        if (rto != RTO_INITIAL_DISABLED)
                sfnet_set_param(PARAM_RTO, &rto);

        sfnet_set_param(PARAM_RTO_DYNAMIC, &rto_dynamic);
*/
        /*
        if (tx_burst != 0)
                sfnet_set_param(PARAM_TX_BURST, &tx_burst);
        */
#if defined(ENABLE_DEBUG)
//        sfnet_set_param(PARAM_DEBUG, &debug);
#endif
out:
        return err;
        /*
          inet_del_protocol(&scaffold_protocol, IPPROTO_SCAFFOLD);
          out_scaffold_protocol_failure:
        */
	sock_unregister(PF_SCAFFOLD);
fail_sock_register:
	proto_unregister(&scaffold_udp_proto);     
fail_proto:
#if defined(__KERNEL__)
fail_netlink:
        unregister_netdevice_notifier(&netdev_notifier);
fail_netdev_notifier:
#endif
        goto out;      
}

void __exit scaffold_fini(void)
{
       
        // Tell SFNet to cleanup and send a leave message
//        sfnet_handle_cleanup();
        
        /* dev_remove_pack(&scaffold_packet_type); */
	/* unregister_inetaddr_notifier(&inetaddr_notifier); */

	/* unregister_netdevice_notifier(&netdev_notifier); */
        /* inet_del_protocol(&scaffold_protocol, IPPROTO_SCAFFOLD); */
#if defined(__KERNEL__)
        scaffold_netlink_fini();
#endif
     	sock_unregister(PF_SCAFFOLD);
	proto_unregister(&scaffold_udp_proto);

        LOG_INF("Unloaded scaffold protocol module\n");
}

#if defined(__KERNEL__)
module_init(scaffold_init)
module_exit(scaffold_fini)

MODULE_ALIAS_NETPROTO(PF_SCAFFOLD);
#endif
