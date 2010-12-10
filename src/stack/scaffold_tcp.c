/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/platform.h>
#include <scaffold/debug.h>
#include <scaffold/skbuff.h>
#include <scaffold/sock.h>
#include <netinet/scaffold.h>
#include <scaffold_tcp_sock.h>
#include <input.h>

#if defined(OS_LINUX_KERNEL)
#include <linux/ip.h>
#include <net/tcp.h>
#endif

#if defined(OS_USER)
#include <netinet/ip.h>
#if defined(OS_BSD)
#include <scaffold/platform_tcpip.h>
#else
#include <netinet/tcp.h>
#endif
#endif /* OS_USER */

static int scaffold_sock_is_valid_conn_state(int state)
{
        return (state == SCAFFOLD_BOUND ||
                state == TCP_FINWAIT1 ||
                state == TCP_FINWAIT2 ||
                state == TCP_SIMCLOSE ||
                state == TCP_LASTACK ||
                state == TCP_CLOSEWAIT);
}

static int scaffold_tcp_init_sock(struct sock *sk)
{
        // struct scaffold_tcp_sock *tsk = scaffold_tcp_sk(sk);
        
        return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
static int scaffold_tcp_destroy_sock(struct sock *sk)
#else
static void scaffold_tcp_destroy_sock(struct sock *sk)
#endif
{
        struct scaffold_tcp_sock *tsk = scaffold_tcp_sk(sk);
   
	__skb_queue_purge(&tsk->out_of_order_queue);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
        return 0;
#endif
}

static void scaffold_tcp_close(struct sock *sk, long timeout)
{
        //struct scaffold_tcp_sock *tsk = scaffold_tcp_sk(sk);
        
        sk_common_release(sk);
}

static int scaffold_tcp_disconnect(struct sock *sk, int flags)
{
        return 0;
}

static void scaffold_tcp_shutdown(struct sock *sk, int how)
{
        LOG_DBG("\n");
        
}

static int scaffold_tcp_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	//struct scaffold_sock *scaff = scaffold_sk(sk);
	int rc;

        LOG_DBG("received data\n");

        // Queue skbs on socket for reading via recv() or recvmsg()
        if ((rc = sock_queue_rcv_skb(sk,skb)) < 0) {
		/* Note that an ENOMEM error is charged twice */
		if (rc == -ENOMEM) {
			// increase stats
                }
		goto drop;
	}
        LOG_DBG("skb queued\n");
        FREE_SKB(skb);
        return 0;
drop:
        LOG_DBG("skb queue error!\n");

        FREE_SKB(skb);

        return -1;
}

/* 
   Receive from network
*/
int scaffold_tcp_rcv(struct sk_buff *skb)
{
	struct sock *sk;
        struct tcphdr *tcph = tcp_hdr(skb);
        struct sock_id *sockid = (struct sock_id *)&tcph->dest;
        int err = 0;
        
        LOG_DBG("tcp packet seq=%lu ack=%lu\n",  
                ntohl(tcph->seq),
                ntohl(tcph->ack_seq));

        sk = scaffold_sock_lookup_sockid(sockid);
        
        if (!sk) {
                LOG_ERR("No matching scaffold sock\n");
                FREE_SKB(skb);
        }

        return err;
}

static int scaffold_tcp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
                                size_t len)
{
        int ret = -ENOMEM;
        struct service_id dst_sid;
        /* Check if we are calling send() or sendto(), i.e., whether
           we are given the destination service id or not. */
        if (msg->msg_name) {
                struct sockaddr_sf *sfaddr = msg->msg_name;
                
                if (sfaddr->sf_family != AF_SCAFFOLD)
                        return -EAFNOSUPPORT;
                
                memcpy(&dst_sid, &sfaddr->sf_srvid, sizeof(struct service_id)); 
        } else {
                memcpy(&dst_sid, &scaffold_sk(sk)->peer_srvid, sizeof(struct service_id));
        }
        
        //LOG_DBG("sendmsg() to serviceId=%u\n", ntohs(dst_oid.s_oid));
               
        lock_sock(sk);
        
        if (sk->sk_state == SCAFFOLD_RECONNECT) {
                release_sock(sk);
                
                LOG_DBG("af_scaffold: in RECONNECT. Waiting...\n");

                ret = wait_event_interruptible(*sk_sleep(sk), sk->sk_state != SCAFFOLD_RECONNECT);
                
                /* Check if we were interrupted */
                if (ret != 0) {
                        LOG_DBG("Interrupted while waiting in RECONNECT\n");
                        return ret;
                }

                lock_sock(sk);
                
                if (sk->sk_state != SCAFFOLD_BOUND)  {
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

static int scaffold_tcp_recvmsg(struct kiocb *iocb, struct sock *sk, 
                                struct msghdr *msg,
                                size_t len, int nonblock, int flags, int *addr_len)
{
        struct sockaddr_sf *sfaddr = (struct sockaddr_sf *)msg->msg_name;
        int retval = -ENOMEM;
	long timeo;
        static size_t tot_bytes_read = 0;

        lock_sock(sk);
       
        if ((unsigned)msg->msg_namelen < sizeof(struct sockaddr_sf)) {
                retval = -EINVAL;
                LOG_DBG("address length is incorrect\n");
                goto out;
        }

	timeo = sock_rcvtimeo(sk, nonblock);
        
	do {
                ssize_t datalen = 0;

                if (!scaffold_sock_is_valid_conn_state(sk->sk_state)) {
                        if (sk->sk_state == SCAFFOLD_RECONNECT) {
                                LOG_DBG("RECONNECT. Waiting\n");
                                
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

                                if (sk->sk_state != SCAFFOLD_BOUND)  {
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
		if (len > (size_t)datalen) {
                        len = datalen;
                }
                
                /* Copy service ids */
                if (sfaddr) {
                        size_t addrlen = msg->msg_namelen;
                        
                        sfaddr->sf_family = AF_SCAFFOLD;
                        msg->msg_namelen = sizeof(struct sockaddr_sf);
                        memcpy(&sfaddr->sf_srvid, 
                               &scaffold_sk(sk)->peer_srvid, 
                               sizeof(struct service_id));

                        /* Copy also our local service id to the
                         * address buffer if size admits */
                        if (addrlen >= sizeof(struct sockaddr_sf) * 2) {
                                sfaddr = (struct sockaddr_sf *)((char *)msg->msg_name + sizeof(struct sockaddr_sf));
                                sfaddr->sf_family = AF_SCAFFOLD;

                                memcpy(&sfaddr->sf_srvid, 
                                       &scaffold_sk(sk)->local_srvid, 
                                       sizeof(struct service_id));
                        }
                }

//                retval = sfnet_handle_recv_socket(sk, msg->msg_iov, len, flags);

                if (retval < 0) {
                        /* Exception. Bailout! */
                        LOG_DBG("could not copy data, len=%zu\n", len);
			break;
		} else if (retval == 0) {
                        LOG_DBG("retval is 0 after recv_socket\n");
                }
                tot_bytes_read += len;
		break;
	} while (1);
out:
        release_sock(sk);

        return retval;
}

struct proto scaffold_tcp_proto = {
	.name			= "SCAFFOLD_TCP",
	.owner			= THIS_MODULE,
        .init                   = scaffold_tcp_init_sock,
        .close                  = scaffold_tcp_close,
        .destroy                = scaffold_tcp_destroy_sock,
	.disconnect		= scaffold_tcp_disconnect,
	.shutdown		= scaffold_tcp_shutdown,
        .sendmsg                = scaffold_tcp_sendmsg,
        .recvmsg                = scaffold_tcp_recvmsg,
	.backlog_rcv		= scaffold_tcp_backlog_rcv,
        .hash                   = scaffold_sock_hash,
        .unhash                 = scaffold_sock_unhash,
	.obj_size		= sizeof(struct scaffold_tcp_sock),
};
