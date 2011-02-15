/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/platform.h>
#include <serval/debug.h>
#include <serval/skbuff.h>
#include <serval/sock.h>
#include <netinet/serval.h>
#include <serval_tcp_sock.h>
#include <serval_srv.h>
#include <input.h>

#if defined(OS_LINUX_KERNEL)
#include <linux/ip.h>
#include <net/tcp.h>
#endif

#if defined(OS_USER)
#include <netinet/ip.h>
#if defined(OS_BSD)
#include <serval/platform_tcpip.h>
#else
#include <netinet/tcp.h>
#endif
#endif /* OS_USER */

static int serval_sock_is_valid_conn_state(int state)
{
        return (state == SERVAL_CONNECTED ||
                state == SERVAL_FINWAIT1 ||
                state == SERVAL_FINWAIT2 ||
                state == SERVAL_LASTACK ||
                state == SERVAL_CLOSEWAIT);
}

static int serval_tcp_init_sock(struct sock *sk)
{
        // struct serval_tcp_sock *tsk = serval_tcp_sk(sk);
        
        return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
static int serval_tcp_destroy_sock(struct sock *sk)
#else
        static void serval_tcp_destroy_sock(struct sock *sk)
#endif
{
        struct serval_tcp_sock *tsk = serval_tcp_sk(sk);
   
	__skb_queue_purge(&tsk->out_of_order_queue);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
        return 0;
#endif
}

static void serval_tcp_close(struct sock *sk, long timeout)
{
        //struct serval_tcp_sock *tsk = serval_tcp_sk(sk);
}

static int serval_tcp_connect(struct sock *sk, struct sockaddr *uaddr, 
                              int addr_len)
{
        LOG_DBG("\n");
        return 0;
}

static int serval_tcp_disconnect(struct sock *sk, int flags)
{
        return 0;
}

static void serval_tcp_shutdown(struct sock *sk, int how)
{
        LOG_DBG("\n");
        
}

/* 
   Receive from network
*/
int serval_tcp_rcv(struct sk_buff *skb)
{
	struct sock *sk;
        struct tcphdr *tcph = tcp_hdr(skb);
        struct flow_id *flowid = (struct flow_id *)&tcph->dest;
        int err = 0;
        
        LOG_DBG("tcp packet seq=%lu ack=%lu\n",  
                ntohl(tcph->seq),
                ntohl(tcph->ack_seq));

        sk = serval_sock_lookup_flowid(flowid);
        
        if (!sk) {
                LOG_ERR("No matching serval sock\n");
                FREE_SKB(skb);
        }

        return err;
}

static int serval_tcp_sendmsg(struct kiocb *iocb, struct sock *sk, 
                              struct msghdr *msg,
                              size_t len)
{
        int ret = -ENOMEM;
        struct service_id dst_sid;
        /* Check if we are calling send() or sendto(), i.e., whether
           we are given the destination service id or not. */
        if (msg->msg_name) {
                struct sockaddr_sv *svaddr = msg->msg_name;
                
                if (svaddr->sv_family != AF_SERVAL)
                        return -EAFNOSUPPORT;
                
                memcpy(&dst_sid, &svaddr->sv_srvid, sizeof(struct service_id)); 
        } else {
                memcpy(&dst_sid, &serval_sk(sk)->peer_srvid, sizeof(struct service_id));
        }
        
        //LOG_DBG("sendmsg() to serviceId=%u\n", ntohs(dst_srvid.s_srvid));
               
        lock_sock(sk);
        
        if (sk->sk_state == SERVAL_RECONNECT) {
                release_sock(sk);
                
                LOG_DBG("af_serval: in RECONNECT. Waiting...\n");

                ret = wait_event_interruptible(*sk_sleep(sk), sk->sk_state != SERVAL_RECONNECT);
                
                /* Check if we were interrupted */
                if (ret != 0) {
                        LOG_DBG("Interrupted while waiting in RECONNECT\n");
                        return ret;
                }

                lock_sock(sk);
                
                if (sk->sk_state != SERVAL_CONNECTED)  {
                        release_sock(sk);
                        return -ENOTCONN;
                }
        }

        //ret = sfnet_handle_send_socket(sk, &dst_srvid, msg->msg_iov, len, msg->msg_flags & MSG_DONTWAIT);

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
                serval_sk(sk)->tot_bytes_sent += len;
        }
        release_sock(sk);

        return ret;
}

static int serval_tcp_recvmsg(struct kiocb *iocb, struct sock *sk, 
                              struct msghdr *msg,
                              size_t len, int nonblock, int flags, int *addr_len)
{
        struct sockaddr_sv *svaddr = (struct sockaddr_sv *)msg->msg_name;
        int retval = -ENOMEM;
	long timeo;
        static size_t tot_bytes_read = 0;

        lock_sock(sk);
       
        if ((unsigned)msg->msg_namelen < sizeof(struct sockaddr_sv)) {
                retval = -EINVAL;
                LOG_DBG("address length is incorrect\n");
                goto out;
        }

	timeo = sock_rcvtimeo(sk, nonblock);
        
	do {
                ssize_t datalen = 0;

                if (!serval_sock_is_valid_conn_state(sk->sk_state)) {
                        if (sk->sk_state == SERVAL_RECONNECT) {
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

                                if (sk->sk_state != SERVAL_CONNECTED)  {
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
                if (svaddr) {
                        size_t addrlen = msg->msg_namelen;
                        
                        svaddr->sv_family = AF_SERVAL;
                        msg->msg_namelen = sizeof(struct sockaddr_sv);
                        memcpy(&svaddr->sv_srvid, 
                               &serval_sk(sk)->peer_srvid, 
                               sizeof(struct service_id));

                        /* Copy also our local service id to the
                         * address buffer if size admits */
                        if (addrlen >= sizeof(struct sockaddr_sv) * 2) {
                                svaddr = (struct sockaddr_sv *)((char *)msg->msg_name + sizeof(struct sockaddr_sv));
                                svaddr->sv_family = AF_SERVAL;

                                memcpy(&svaddr->sv_srvid, 
                                       &serval_sk(sk)->local_srvid, 
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

struct proto serval_tcp_proto = {
	.name			= "SERVAL_TCP",
	.owner			= THIS_MODULE,
        .init                   = serval_tcp_init_sock,
        .close                  = serval_tcp_close,
        .destroy                = serval_tcp_destroy_sock,
	.connect		= serval_tcp_connect,
	.disconnect		= serval_tcp_disconnect,
	.shutdown		= serval_tcp_shutdown,
        .sendmsg                = serval_tcp_sendmsg,
        .recvmsg                = serval_tcp_recvmsg,
	.backlog_rcv		= serval_srv_do_rcv,
        .hash                   = serval_sock_hash,
        .unhash                 = serval_sock_unhash,
	.obj_size		= sizeof(struct serval_tcp_sock),
};
