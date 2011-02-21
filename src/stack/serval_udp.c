/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/platform.h>
#include <serval/debug.h>
#include <serval/netdevice.h>
#include <serval/skbuff.h>
#include <netinet/serval.h>
#include <serval_udp_sock.h>
#include <serval_sock.h>
#include <serval_request_sock.h>
#include <serval_ipv4.h>
#include <serval_srv.h>
#include <input.h>

#if defined(OS_LINUX_KERNEL)
#include <linux/ip.h>
#include <net/udp.h>
#endif

#if defined(OS_USER)
#include <netinet/ip.h>
#if defined(OS_BSD)
#include <serval/platform_tcpip.h>
#else
#include <netinet/udp.h>
#endif
#endif /* OS_USER */

#define EXTRA_HDR (20)
/* payload + LL + IP + extra */
#define UDP_MAX_HDR (MAX_HEADER + 20 + EXTRA_HDR +      \
                     sizeof(struct serval_hdr)) 

static int serval_udp_connection_request(struct sock *sk, 
                                         struct sk_buff *skb);

static void serval_udp_connection_respond_sock(struct sock *sk, 
                                                struct sk_buff *skb,
                                                struct sock *child,
                                               struct dst_entry *dst);

static int serval_udp_rcv(struct sock *sk, struct sk_buff *skb);

static struct serval_sock_af_ops serval_udp_af_ops = {
        .queue_xmit = serval_ipv4_xmit_skb,
        .receive = serval_udp_rcv,
        .conn_request = serval_udp_connection_request,
        .conn_child_sock = serval_udp_connection_respond_sock,
};

/* from fastudpsrc */
static void udp_checksum(uint16_t total_len,
                         struct udphdr *uh, void *data) 
{
        uint32_t src = *(uint32_t *)data;
        unsigned short len = total_len - 14 - sizeof(struct iphdr);
        unsigned csum = 0; 
        uh->check = 0;
        /* FIXME: Do not assume IP header lacks options */
        csum = ~in_cksum((unsigned char *)uh, len) & 0xFFFF;
        csum += src & 0xFFFF;
        csum += (src >> 16) & 0xFFFF;
        csum += htons(SERVAL_PROTO_UDP) + htons(len);
        csum = (csum & 0xFFFF) + (csum >> 16);
        uh->check = ~csum & 0xFFFF;
}

static int serval_udp_transmit_skb(struct sock *sk, 
                                   struct sk_buff *skb,
                                   enum serval_packet_type type)
{
        int err;
        unsigned short tot_len;
        struct udphdr *uh;

        /* Push back to make space for transport header */
        uh = (struct udphdr *)skb_push(skb, sizeof(struct udphdr));
	skb_reset_transport_header(skb);
        SERVAL_SKB_CB(skb)->pkttype = type;
        
        tot_len = skb->len + 20 + 14;
        
        /* Build UDP header */
        uh->source = 0;
        uh->dest = 0;
        uh->len = htons(skb->len);
        udp_checksum(tot_len, uh, &serval_sk(sk)->src_addr);
        
        skb->protocol = IPPROTO_UDP;

        LOG_DBG("udp pkt [s=%u d=%u len=%u]\n",
                ntohs(uh->source),
                ntohs(uh->dest),
                ntohs(uh->len));

        err = serval_srv_xmit_skb(skb);
        
        if (err < 0) {
                LOG_ERR("xmit failed\n");
        }

        return err;
}

static int serval_udp_init_sock(struct sock *sk)
{
        struct serval_sock *ssk = serval_sk(sk);

        ssk->af_ops = &serval_udp_af_ops;

        LOG_DBG("\n");
        
        return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
static int serval_udp_destroy_sock(struct sock *sk)
#else
static void serval_udp_destroy_sock(struct sock *sk)
#endif
{
        //struct serval_udp_sock *usk = serval_udp_sk(sk);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
        return 0;
#endif
}

static int serval_udp_disconnect(struct sock *sk, int flags)
{

        LOG_DBG("\n");
        
        return 0;
}

static void serval_udp_shutdown(struct sock *sk, int how)
{
        LOG_DBG("\n");
}

int serval_udp_connection_request(struct sock *sk, struct sk_buff *skb)
{
        //struct serval_sock *ssk = serval_sk(sk);
        /* struct iphdr *iph = ip_hdr(skb);
           struct udphdr *udph = udp_hdr(skb); */

        int err = 0;

        LOG_DBG("SYN received\n");

        return err;
}

void serval_udp_connection_respond_sock(struct sock *sk, 
                                        struct sk_buff *skb,
                                        struct sock *child,
                                        struct dst_entry *dst)
{
}

/* 
   Receive from network
*/
int serval_udp_rcv(struct sock *sk, struct sk_buff *skb)
{
        struct udphdr *udph = udp_hdr(skb);
        unsigned short datalen = ntohs(udph->len) - sizeof(*udph);
        int err = 0;
        
        /* Only ignore this message in case it has zero length and is
         * not a FIN */
        if (datalen == 0 && 
            SERVAL_SKB_CB(skb)->pkttype != SERVAL_PKT_CLOSE) {
                FREE_SKB(skb);
                return 0;
        }

        pskb_pull(skb, sizeof(*udph));

        /* LOG_DBG("data len=%u skb->len=%u\n", datalen, skb->len); */
        
        /* Ideally, this trimming would not be necessary. However, it
         * seems that somewhere in the receive process trailing
         * bytes are added to the packet. Perhaps this is a result of
         * PACKET sockets, and for efficiency the return full words or
         * something? Anyway, we can live with this for now... */
        if (datalen < skb->len) {
                pskb_trim(skb, datalen);
        }

        /* Increase readable memory */
        skb_set_owner_r(skb, sk);
        skb_queue_tail(&sk->sk_receive_queue, skb);
        sk->sk_data_ready(sk, datalen);

        return err;
}

static int serval_udp_sendmsg(struct kiocb *iocb, struct sock *sk, 
                              struct msghdr *msg, size_t len)
{
        int err;
        struct sk_buff *skb;
        int ulen = len;
        struct service_id *srvid = NULL;
        struct net_addr *netaddr = NULL;

	if (len > 0xFFFF )
		return -EMSGSIZE;

        if (len == 0)
                return -EINVAL;

	if (msg->msg_flags & MSG_OOB) 
		return -EOPNOTSUPP;

	if (msg->msg_name) {
		struct sockaddr_sv *svaddr = 
                        (struct sockaddr_sv *)msg->msg_name;
                struct sockaddr_in *inaddr = 
                        (struct sockaddr_in *)(svaddr + 1);

		if ((unsigned)msg->msg_namelen < sizeof(*svaddr))
			return -EINVAL;

		if (svaddr->sv_family != AF_SERVAL) {
			if (svaddr->sv_family != AF_UNSPEC)
				return -EAFNOSUPPORT;
		}
                
                srvid = &svaddr->sv_srvid;
                
                /* Check for advisory IP address */
                if ((unsigned)msg->msg_namelen >= 
                    (sizeof(*svaddr) + sizeof(*inaddr))) {
                        char buf[20];
                                
                        if (inaddr->sin_family != AF_INET)
                                return -EAFNOSUPPORT;

                        LOG_DBG("Advisory IP %s\n",
                                inet_ntop(inaddr->sin_family, 
                                          &inaddr->sin_addr,
                                          buf, sizeof(buf)));
                        
                        netaddr = (struct net_addr *)&inaddr->sin_addr;
                }
        } else if (sk->sk_state != SERVAL_CONNECTED) {
                return -EDESTADDRREQ;
        }

        ulen += sizeof(struct udphdr);

        skb = sock_alloc_send_skb(sk, UDP_MAX_HDR + ulen,
                                  (msg->msg_flags & MSG_DONTWAIT), &err);

        if (!skb)
                return -ENOMEM;
        
        skb_reserve(skb, UDP_MAX_HDR);

        if (srvid) {
                memcpy(&SERVAL_SKB_CB(skb)->srvid, srvid, sizeof(*srvid));
        }
        if (netaddr) {
                memcpy(&SERVAL_SKB_CB(skb)->addr, netaddr, sizeof(*netaddr));
        } else {
                /* Make sure we zero this address to signal it is unset */
                memset(&SERVAL_SKB_CB(skb)->addr, 0, sizeof(*netaddr));
        }
        /* 
           TODO: 
           
           This is an extra copy operation for the user space version
           that we could try to get rid of, i.e., reading the data
           from the file descriptor directly into the socket buffer
        */
        
        err = memcpy_fromiovec(skb_put(skb, len), msg->msg_iov, len);
     
        if (err < 0) {
                LOG_ERR("could not copy user data to skb\n");
                FREE_SKB(skb);
                goto out;
        }

        lock_sock(sk);
                
        err = serval_udp_transmit_skb(sk, skb, SERVAL_PKT_DATA);
        
        if (err < 0) {
                LOG_ERR("xmit failed\n");
        }

        release_sock(sk);
out:
        return err;
}

static int serval_udp_recvmsg(struct kiocb *iocb, struct sock *sk, 
                              struct msghdr *msg, size_t len, int nonblock, 
                              int flags, int *addr_len)
{
        struct sockaddr_sv *svaddr = (struct sockaddr_sv *)msg->msg_name;
        int retval = -ENOMEM;
	long timeo;
        
        lock_sock(sk);
        
        if (sk->sk_state == SERVAL_CLOSED) {
                /* SERVAL_CLOSED is a valid state here because recvmsg
                 * should return 0 and not an error */
		retval = -ENOTCONN;
		goto out;
	}

        if ((unsigned)msg->msg_namelen < sizeof(struct sockaddr_sv)) {
                retval = -EINVAL;
                LOG_DBG("address length is incorrect\n");
                goto out;
        }

	timeo = sock_rcvtimeo(sk, nonblock);

	do {                
		struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);

		if (skb)
			goto found_ok_skb;
	
                if (sk->sk_err) {
                        retval = sock_error(sk);
                        break;
                }

                if (sk->sk_shutdown & RCV_SHUTDOWN) {
                        retval = 0;
                        break;
                }

		if (sk->sk_state == SERVAL_CLOSED) {
			if (!sock_flag(sk, SOCK_DONE)) {
				retval = -ENOTCONN;
				break;
			}
                        
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

                sk_wait_data(sk, &timeo);
		continue;
	found_ok_skb:
                if (SERVAL_SKB_CB(skb)->pkttype == SERVAL_PKT_CLOSE) {
                        retval = 0;
                        goto found_fin_ok;
                }

		if (len >= skb->len) {
			retval = skb->len;
                        len = skb->len;
                } else if (len < skb->len) {
			msg->msg_flags |= MSG_TRUNC;
                        retval = len;
                }
                
                /* Copy service id */
                if (svaddr) {
                        size_t addrlen = msg->msg_namelen;

                        svaddr->sv_family = AF_SERVAL;
                        *addr_len = sizeof(*svaddr);
                        memcpy(&svaddr->sv_srvid, &SERVAL_SKB_CB(skb)->srvid, 
                               sizeof(svaddr->sv_srvid));
                        
                        /* Copy also IP address if possible */
                        if (addrlen == (sizeof(*svaddr) + 
                                        sizeof(struct sockaddr_in))) {
                                struct sockaddr_in *inaddr = 
                                        (struct sockaddr_in *)(svaddr + 1);
                                inaddr->sin_family = AF_INET;
                                memcpy(&inaddr->sin_addr, &ip_hdr(skb)->saddr,
                                       sizeof(ip_hdr(skb)->saddr));
                                *addr_len +=sizeof(*inaddr);
                        }
                }
                                
		if (skb_copy_datagram_iovec(skb, 0, msg->msg_iov, len)) {
			/* Exception. Bailout! */
			retval = -EFAULT;
                        LOG_DBG("could not copy data, len=%zu\n", len);
			break;
		}
        found_fin_ok:
		if (!(flags & MSG_PEEK))
			sk_eat_skb(sk, skb, 0);
		break;
	} while (1);
out:
        release_sock(sk);
        
        return retval;
}

struct proto serval_udp_proto = {
	.name			= "SERVAL_UDP",
	.owner			= THIS_MODULE,
        .init                   = serval_udp_init_sock,
        .destroy                = serval_udp_destroy_sock,        
	.close  		= serval_srv_close,   
        .connect                = serval_srv_connect,
	.disconnect 		= serval_udp_disconnect,
	.shutdown		= serval_udp_shutdown,
        .sendmsg                = serval_udp_sendmsg,
        .recvmsg                = serval_udp_recvmsg,
	.backlog_rcv		= serval_srv_do_rcv,
        .hash                   = serval_sock_hash,
        .unhash                 = serval_sock_unhash,
	.obj_size		= sizeof(struct serval_udp_sock),
};
