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
#include <serval_sal.h>
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
#define MAX_SERVAL_UDP_HDR (MAX_SERVAL_HDR + sizeof(struct udphdr)) 

static int serval_udp_connection_request(struct sock *sk,
                                         struct request_sock *rsk,
                                         struct sk_buff *skb);

static int serval_udp_connection_respond_sock(struct sock *sk, 
                                              struct sk_buff *skb,
                                              struct request_sock *rsk,
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
        udp_checksum(tot_len, uh, &inet_sk(sk)->inet_saddr);
        
        skb->protocol = IPPROTO_UDP;
        
        LOG_PKT("udp pkt [s=%u d=%u len=%u]\n",
                ntohs(uh->source),
                ntohs(uh->dest),
                ntohs(uh->len));

        err = serval_sal_xmit_skb(skb);
        
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

int serval_udp_connection_request(struct sock *sk, 
                                  struct request_sock *rsk,
                                  struct sk_buff *skb)
{
        return 0;
}

int serval_udp_connection_respond_sock(struct sock *sk, 
                                       struct sk_buff *skb,
                                       struct request_sock *rsk,
                                       struct sock *child,
                                       struct dst_entry *dst)
{
        return 0;
}

/* 
   Receive from network.
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

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35))
        /* Drop if receive queue is full. Dropping due to full queue
         * is done below in sock_queue_rcv for those kernel versions
         * that do not define this sk_rcvqueues_full().  */
        if (sk_rcvqueues_full(sk, skb)) {
                FREE_SKB(skb);
                return -ENOBUFS; 
        }
#endif
        pskb_pull(skb, sizeof(*udph));

        
        LOG_DBG("data len=%u skb->len=%u\n",
                datalen, skb->len); 
                
        /* Ideally, this trimming would not be necessary. However, it
         * seems that somewhere in the receive process trailing
         * bytes are added to the packet. Perhaps this is a result of
         * PACKET sockets, and for efficiency the return full words or
         * something? Anyway, we can live with this for now... */
        if (datalen < skb->len) {
                pskb_trim(skb, datalen);
        }

        /* 
           sock_queue_rcv_skb() will increase readable memory (i.e.,
           decrease free receive buffer memory), do socket filtering
           and wake user process.
        */
        err = sock_queue_rcv_skb(sk, skb);

        if (err < 0) {
                /* Increase error statistics. These are standard
                 * macros defined for standard UDP. */
                if (err == -ENOMEM) {
                        /* TODO: statistics */
                }
                FREE_SKB(skb);
        }

        return err;
}

static int serval_udp_sendmsg(struct kiocb *iocb, struct sock *sk, 
                              struct msghdr *msg, size_t len)
{
        int err;
        struct sk_buff *skb;
        struct service_id *srvid = NULL;
        struct net_addr *netaddr = NULL;
        int nonblock = msg->msg_flags & MSG_DONTWAIT;
        long timeo;

	if (len > 0xFFFF)
		return -EMSGSIZE;

        if (len == 0)
                return -EINVAL;

	if (msg->msg_flags & MSG_OOB) 
		return -EOPNOTSUPP;

	if (msg->msg_name) {
		struct sockaddr_sv *svaddr = (struct sockaddr_sv *)msg->msg_name;
                struct sockaddr_in *inaddr = (struct sockaddr_in *)(svaddr + 1);

		if ((unsigned)msg->msg_namelen < sizeof(*svaddr))
			return -EINVAL;

		if (svaddr->sv_family != AF_SERVAL) {
			if (svaddr->sv_family != AF_UNSPEC)
				return -EAFNOSUPPORT;
		}
                
                srvid = &svaddr->sv_srvid;

                /* Check for advisory IP address */
                LOG_DBG("dest sid: %s, sock addr len: %i\n",
                        service_id_to_str(&svaddr->sv_srvid), 
                        msg->msg_namelen);

                if ((unsigned)msg->msg_namelen >=
                    (sizeof(*svaddr) + sizeof(*inaddr))) {

                        if (inaddr->sin_family != AF_INET)
                                return -EAFNOSUPPORT;
#if defined(ENABLE_DEBUG)
                        {
                                char buf[20];
                                LOG_DBG("Advisory IP %s\n",
                                        inet_ntop(inaddr->sin_family,
                                                  &inaddr->sin_addr,
                                                  buf, sizeof(buf)));
                        }
#endif
                        netaddr = (struct net_addr *)&inaddr->sin_addr;
                }
        } else if (sk->sk_state != SERVAL_CONNECTED) {
                return -EDESTADDRREQ;
        }

        lock_sock(sk);

	timeo = sock_sndtimeo(sk, nonblock);

	/* Wait for a connection to finish. */
	if ((1 << sk->sk_state) & SERVALF_REQUEST)
		if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)
                        goto out;

        skb = sock_alloc_send_skb(sk, sk->sk_prot->max_header + len, 
                                  nonblock, &err);

        if (!skb)
                goto out;
        
        skb_reserve(skb, sk->sk_prot->max_header);

        if (srvid) {
                memcpy(&SERVAL_SKB_CB(skb)->srvid, srvid, sizeof(*srvid));
        }
        if (netaddr) {
                memcpy(&SERVAL_SKB_CB(skb)->addr, netaddr, sizeof(*netaddr));
        } else {
                /* Make sure we zero this address to signal it is unset */
                memset(&SERVAL_SKB_CB(skb)->addr, 0, sizeof(*netaddr));
        }

        err = memcpy_fromiovec(skb_put(skb, len), msg->msg_iov, len);
     
        if (err < 0) {
                LOG_ERR("could not copy user data to skb\n");
                FREE_SKB(skb);
                goto out;
        }

        err = serval_udp_transmit_skb(sk, skb, SERVAL_PKT_DATA);
        
        if (err < 0) {
                LOG_ERR("xmit failed\n");
        }
 out:
        release_sock(sk);

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
                        LOG_ERR("sk=%p error=%d\n",
                                sk, retval);
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
			LOG_DBG("signal pending failed here\n");
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
                        if (addrlen >= (sizeof(*svaddr) +
                                        sizeof(struct sockaddr_in))) {
                                struct sockaddr_in *inaddr =
                                        (struct sockaddr_in *)(svaddr + 1);
                                inaddr->sin_family = AF_INET;
                                memcpy(&inaddr->sin_addr, &ip_hdr(skb)->saddr,
                                       sizeof(ip_hdr(skb)->saddr));
                                *addr_len += sizeof(*inaddr);
                        }
                }
                                
		if (skb_copy_datagram_iovec(skb, 0, msg->msg_iov, len)) {
			/* Exception. Bailout! */
			retval = -EFAULT;
                        LOG_DBG("could not copy data, len=%zu\n", len);
			break;
		}
        found_fin_ok:
		if (!(flags & MSG_PEEK)) {
			sk_eat_skb(sk, skb, 0);
                        /*
                          Only for stream-based memory accounting? 
                        sk_mem_reclaim_partial(sk);
                        */
                }
		break;
	} while (1);
 out:
        release_sock(sk);
        LOG_DBG("final retval: %i\n", retval);
        return retval;
}

#if defined(OS_LINUX_KERNEL) && defined(ENABLE_SPLICE)
/*
 * UDP splice context
 */
struct udp_splice_state {
	struct pipe_inode_info *pipe;
	size_t len;
	unsigned int flags;
};

typedef int (*sk_read_actor_t)(read_descriptor_t *, struct sk_buff *,
                               unsigned int, size_t);

extern int skb_splice_bits(struct sk_buff *skb, unsigned int offset,
                           struct pipe_inode_info *pipe, unsigned int tlen,
                           unsigned int flags);

static int serval_udp_splice_data_recv(read_descriptor_t *rd_desc, 
                                       struct sk_buff *skb,
                                       unsigned int offset, size_t len)
{
	struct udp_splice_state *tss = rd_desc->arg.data;
	int ret;

	ret = skb_splice_bits(skb, offset, tss->pipe,
                              min(rd_desc->count, len), tss->flags);
	if (ret > 0)
		rd_desc->count -= ret;
	return ret;
}

/*
 * This routine provides an alternative to serval_udp_recvmsg() for
 * routines that would like to handle copying from skbuffs directly in
 * 'sendfile' fashion.
 * Note:
 *	- It is assumed that the socket was locked by the caller.
 *	- The routine does not block.
 *	- At present, there is no support for reading OOB data
 *	  or for 'peeking' the socket using this routine
 *	  (although both would be easy to implement).
 */
int serval_udp_read_sock(struct sock *sk, read_descriptor_t *desc,
                         sk_read_actor_t recv_actor)
{
	struct sk_buff *skb;
	int retval = 0;

	if (sk->sk_state == SERVAL_LISTEN)
		return -ENOTCONN;

        skb = skb_peek(&sk->sk_receive_queue);
        
        if (!skb)
                return 0;
        
        if (SERVAL_SKB_CB(skb)->pkttype == SERVAL_PKT_CLOSE) {
                retval = 0;
        } else {
                retval = recv_actor(desc, skb, 0, skb->len);
                
                //skb = skb_peek(&sk->sk_receive_queue);
                /*
                 * If recv_actor drops the lock (e.g. TCP splice
                 * receive) the skb pointer might be invalid when
                 * getting here: tcp_collapse might have deleted it
                 * while aggregating skbs from the socket queue.
                 */
        }
        sk_eat_skb(sk, skb, 0);

	return retval;
}

static int __serval_udp_splice_read(struct sock *sk,
                                    struct udp_splice_state *tss)
{
	/* Store TCP splice context information in read_descriptor_t. */
	read_descriptor_t rd_desc = {
		.arg.data = tss,
		.count	  = tss->len,
	};

	return serval_udp_read_sock(sk, &rd_desc, serval_udp_splice_data_recv);
}

/**
 *  serval_udp_splice_read - splice data from DGRAM socket to a pipe
 * @sock:	socket to splice from
 * @ppos:	position (not valid)
 * @pipe:	pipe to splice to
 * @len:	number of bytes to splice
 * @flags:	splice modifier flags
 *
 * Description:
 *    Will read pages from given socket and fill them into a pipe.
 *
 **/
ssize_t serval_udp_splice_read(struct socket *sock, loff_t *ppos,
                               struct pipe_inode_info *pipe, size_t len,
                               unsigned int flags)
{
	struct sock *sk = sock->sk;
	struct udp_splice_state tss = {
		.pipe = pipe,
		.len = len,
		.flags = flags,
	};
	long timeo;
	ssize_t spliced;
	int ret;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35))
	sock_rps_record_flow(sk);
#endif
	/*
	 * We can't seek on a socket input
	 */
	if (unlikely(*ppos))
		return -ESPIPE;

	ret = spliced = 0;

	lock_sock(sk);

	timeo = sock_rcvtimeo(sk, sock->file->f_flags & O_NONBLOCK);

	while (tss.len) {
		ret = __serval_udp_splice_read(sk, &tss);
		if (ret < 0)
			break;
		else if (!ret) {
			if (spliced)
				break;
			if (sock_flag(sk, SOCK_DONE))
				break;
			if (sk->sk_err) {
				ret = sock_error(sk);
				break;
			}
			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;
			if (sk->sk_state == SERVAL_CLOSED) {
				/*
				 * This occurs when user tries to read
				 * from never connected socket.
				 */
				if (!sock_flag(sk, SOCK_DONE))
					ret = -ENOTCONN;
				break;
			}
			if (!timeo) {
				ret = -EAGAIN;
				break;
			}
			sk_wait_data(sk, &timeo);
			if (signal_pending(current)) {
				ret = sock_intr_errno(timeo);
				break;
			}
			continue;
		}
		tss.len -= ret;
		spliced += ret;

		if (!timeo)
			break;
		release_sock(sk);
		lock_sock(sk);

		if (sk->sk_err || sk->sk_state == SERVAL_CLOSED ||
		    (sk->sk_shutdown & RCV_SHUTDOWN) ||
		    signal_pending(current))
			break;
	}

	release_sock(sk);
        /*
          LOG_DBG("spliced=%zu ret=%d\n", spliced, ret);
        */
	if (spliced)
		return spliced;

	return ret;
}

static ssize_t serval_udp_do_sendpages(struct sock *sk, struct page **pages, 
                                       int poffset, size_t psize, int flags)
{
	int err;
	ssize_t copied = 0;
        int nonblock = flags & MSG_DONTWAIT;
	long timeo = sock_sndtimeo(sk, nonblock);

        if (sk->sk_state == SERVAL_INIT) {
                err = -ENOTCONN;
                goto out_err;
        }

	/* Wait for a connection to finish. */
	if ((1 << sk->sk_state) & (SERVALF_REQUEST))
		if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)
			goto out_err;

        if (psize > 0xffff) {
                LOG_ERR("Too much data\n");
                err = -ENOMEM;
                goto out_err;
        }
	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	err = -EPIPE;

	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto out_err;

        /*
          This code is adapted from do_tcp_sendpages and is currently
          very much experimental. This needs some serious cleanups
          before ready.
        */
	while (psize > 0) {
		struct sk_buff *skb;
		struct page *page = pages[poffset / PAGE_SIZE];
		int offset = poffset % PAGE_SIZE;
		int size = min_t(size_t, psize, PAGE_SIZE - offset);

                skb = alloc_skb_fclone(sk->sk_prot->max_header, GFP_ATOMIC);

                if (!skb) {
                        goto out_err;
                }

                skb_reserve(skb, sk->sk_prot->max_header);
                
                /* Make sure we zero this address to signal it is unset */
                memset(&SERVAL_SKB_CB(skb)->addr, 0, 4);

                get_page(page);
                skb_fill_page_desc(skb, 0, page, offset, size);
                skb->len += size;
                skb->data_len += size;
                skb->truesize += size;
		skb->ip_summed = CHECKSUM_NONE;
		skb_shinfo(skb)->gso_segs = 0;
                skb_set_owner_w(skb, sk);
                copied += size;
		poffset += size;
                
                /* FIXME: we only handle one page at this time... Must
                 * really clean up this code. */

                err = serval_udp_transmit_skb(sk, skb, SERVAL_PKT_DATA);
                
                if (err < 0) {
                        LOG_ERR("xmit failed\n");
                }
                break;
	}

        return copied;
 out_err:
        LOG_ERR("Error\n");
	return sk_stream_error(sk, flags, err);
}

ssize_t serval_udp_sendpage(struct socket *sock, struct page *page, int offset,
                            size_t size, int flags)
{
	ssize_t res;
	struct sock *sk = sock->sk;

	if (!(sk->sk_route_caps & NETIF_F_SG) ||
	    !(sk->sk_route_caps & NETIF_F_ALL_CSUM))
		return sock_no_sendpage(sock, page, offset, size, flags);

	lock_sock(sk);
	res = serval_udp_do_sendpages(sk, &page, offset, size, flags);
	release_sock(sk);
        
	return res;
}
#endif /* ENABLE_SPLICE */

static void serval_udp_request_sock_destructor(struct request_sock *rsk)
{
}

struct request_sock_ops udp_request_sock_ops __read_mostly = {
	.family		=	PF_INET,
	.obj_size	=	sizeof(struct serval_request_sock),
        .destructor     =       serval_udp_request_sock_destructor,
};

struct proto serval_udp_proto = {
	.name			= "SERVAL_UDP",
	.owner			= THIS_MODULE,
        .init                   = serval_udp_init_sock,
        .destroy                = serval_udp_destroy_sock,
	.close  		= serval_sal_close,   
        .connect                = serval_sal_connect,
	.disconnect 		= serval_udp_disconnect,
	.shutdown		= serval_udp_shutdown,
        .sendmsg                = serval_udp_sendmsg,
        .recvmsg                = serval_udp_recvmsg,
	.backlog_rcv		= serval_sal_do_rcv,
        .hash                   = serval_sock_hash,
        .unhash                 = serval_sock_unhash,
	.max_header		= MAX_SERVAL_UDP_HDR,
	.obj_size		= sizeof(struct serval_udp_sock),
	.rsk_prot		= &udp_request_sock_ops,
};
