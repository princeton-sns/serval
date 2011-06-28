/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/platform.h>
#include <serval/debug.h>
#include <serval/netdevice.h>
#include <serval/skbuff.h>
#include <serval/sock.h>
#include <serval/net.h>
#include <serval/bitops.h>
#include <netinet/serval.h>
#include <serval_tcp_sock.h>
#include <serval_tcp_request_sock.h>
#include <serval_sal.h>
#include <serval_ipv4.h>
#include <serval_tcp.h>

#if defined(OS_LINUX_KERNEL)
#include <net/netdma.h>
#define ENABLE_PAGE 1
#endif

int sysctl_serval_tcp_fin_timeout __read_mostly = TCP_FIN_TIMEOUT;

int sysctl_serval_tcp_low_latency __read_mostly = 0;

/*
int sysctl_serval_tcp_mem[3];
int sysctl_serval_tcp_wmem[3];
int sysctl_serval_tcp_rmem[3];
*/

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37))
atomic_t serval_tcp_memory_allocated __read_mostly;
#else
atomic_long_t serval_tcp_memory_allocated  __read_mostly;
#endif

static int serval_tcp_disconnect(struct sock *sk, int flags)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
        int err = 0;

	serval_tcp_clear_xmit_timers(sk);
	__skb_queue_purge(&sk->sk_receive_queue);
	serval_tcp_write_queue_purge(sk);
	__skb_queue_purge(&tp->out_of_order_queue);
#ifdef CONFIG_NET_DMA
	__skb_queue_purge(&sk->sk_async_wait_queue);
#endif
        tp->srtt = 0;
	if ((tp->write_seq += tp->max_window + 2) == 0)
		tp->write_seq = 1;
	tp->backoff = 0;
	tp->snd_cwnd = 2;
	tp->probes_out = 0;
	tp->packets_out = 0;
	tp->snd_ssthresh = SERVAL_TCP_INFINITE_SSTHRESH;
	tp->snd_cwnd_cnt = 0;
	tp->bytes_acked = 0;
	tp->window_clamp = 0;
	serval_tcp_set_ca_state(sk, TCP_CA_Open);
	serval_tcp_clear_retrans(tp);
	serval_tsk_delack_init(sk);
	serval_tcp_init_send_head(sk);
	memset(&tp->rx_opt, 0, sizeof(tp->rx_opt));
	__sk_dst_reset(sk);

	sk->sk_error_report(sk);

        return err;
}

static void serval_tcp_shutdown(struct sock *sk, int how)
{
        LOG_DBG("\n");
        
}

__u32 serval_tcp_random_sequence_number(void)
{
   __u32 isn;

#if defined(OS_LINUX_KERNEL)
        get_random_bytes(&isn, sizeof(isn));
#else
        {
                unsigned int i;
                unsigned char *seqno = (unsigned char *)&isn;
              
                for (i = 0; i < sizeof(isn); i++) {
                        seqno[i] = random() & 0xff;
                }
        }       
#endif
        return isn;
}

static inline __u32 serval_tcp_init_sequence(struct sk_buff *skb)
{
        return serval_tcp_random_sequence_number();
}

static inline void serval_tcp_openreq_init(struct request_sock *req,
                                           struct serval_tcp_options_received *rx_opt,
                                           struct sk_buff *skb)
{
	struct inet_request_sock *ireq = inet_rsk(req);

	req->rcv_wnd = 0;		/* So that tcp_send_synack() knows! */
	req->cookie_ts = 0;
	serval_tcp_rsk(req)->rcv_isn = ntohl(tcp_hdr(skb)->seq);

	req->mss = rx_opt->mss_clamp;
	req->ts_recent = rx_opt->saw_tstamp ? rx_opt->rcv_tsval : 0;
	ireq->tstamp_ok = rx_opt->tstamp_ok;
	ireq->sack_ok = rx_opt->sack_ok;
	ireq->snd_wscale = rx_opt->snd_wscale;
	ireq->wscale_ok = rx_opt->wscale_ok;
      
	ireq->tstamp_ok = rx_opt->tstamp_ok;
	ireq->sack_ok = rx_opt->sack_ok;
	ireq->snd_wscale = rx_opt->snd_wscale;
	ireq->wscale_ok = rx_opt->wscale_ok;
	ireq->acked = 0;
	ireq->ecn_ok = 0;
	ireq->rmt_port = tcp_hdr(skb)->source;
	ireq->loc_port = tcp_hdr(skb)->dest;
}


static int serval_tcp_connection_request(struct sock *sk, 
                                         struct request_sock *req,
                                         struct sk_buff *skb)
{
        struct serval_tcp_sock *tp = serval_tcp_sk(sk);
        struct serval_tcp_request_sock *trsk = serval_tcp_rsk(req);
        struct tcphdr *th;
	struct serval_tcp_options_received tmp_opt;
        
        if (!pskb_may_pull(skb, sizeof(struct tcphdr))) {
                LOG_ERR("No TCP header?\n");
                return -1;
        }

        th = tcp_hdr(skb);

        LOG_DBG("TCP SYN received seq=%u src=%u dst=%u skb->len=%u\n", 
                ntohl(th->seq),
                ntohs(th->source),
                ntohs(th->dest),
                skb->len);

        memset(&tmp_opt, 0, sizeof(tmp_opt));
	serval_tcp_clear_options(&tmp_opt);
	tmp_opt.mss_clamp = SERVAL_TCP_MSS_DEFAULT;
	tmp_opt.user_mss  = tp->rx_opt.user_mss;
	//tcp_parse_options(skb, &tmp_opt, &hash_location, 0);

        serval_tcp_openreq_init(req, &tmp_opt, skb);

        trsk->snt_isn = serval_tcp_init_sequence(skb);

        return 0;
}

static int serval_tcp_connection_respond_sock(struct sock *sk, 
                                              struct sk_buff *skb,
                                              struct request_sock *rsk,
                                              struct sock *child,
                                              struct dst_entry *dst);

int serval_tcp_do_rcv(struct sock *sk, struct sk_buff *skb)
{
        int err = 0;
        
        if (sk->sk_state == TCP_ESTABLISHED) { /* Fast path */
		//sock_rps_save_rxhash(sk, skb->rxhash);
		TCP_CHECK_TIMER(sk);

                LOG_DBG("Established state receive\n");
              
		if (serval_tcp_rcv_established(sk, skb, 
                                               tcp_hdr(skb), skb->len)) {
                        err = -1;
			goto reset;
		}
		TCP_CHECK_TIMER(sk);
		return 0;
	} 

	TCP_CHECK_TIMER(sk);

	if (serval_tcp_rcv_state_process(sk, skb, tcp_hdr(skb), skb->len)) {
                err = -1;
		goto reset;
	}
	TCP_CHECK_TIMER(sk);

        return 0;
reset:
        //LOG_WARN("Should handle RESET in non-established state\n");
        __kfree_skb(skb);
        return err;
}

static __sum16 serval_tcp_v4_checksum_init(struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);

	if (skb->ip_summed == CHECKSUM_COMPLETE) {
		if (!serval_tcp_v4_check(skb->len, iph->saddr,
				  iph->daddr, skb->csum)) {
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			return 0;
		}
	}

	skb->csum = csum_tcpudp_nofold(iph->saddr, iph->daddr,
				       skb->len, IPPROTO_TCP, 0);

	if (skb->len <= 76) {
		return __skb_checksum_complete(skb);
	}
	return 0;
}
/* 
   Receive from network.

   TODO/NOTE:

   Since we are adding packets to the backlog in the SAL, and not here
   in the transport receive function, we cannot drop packets with bad
   transport headers before adding to the backlog. Ideally, we would
   not bother queueing bad packets on the backlog, but this requires a
   way to check transport headers before backlogging.

   We could add an "early-packet-sanity-check" function in transport
   that the SAL calls before adding packets to the backlog just to
   make sure they are not bad. This function would basically have the
   checks in the beginning of the function below.

*/
static int serval_tcp_rcv(struct sock *sk, struct sk_buff *skb)
{
        struct tcphdr *th;
        struct iphdr *iph;
        int err = 0;
        
#if defined(OS_LINUX_KERNEL)
	if (skb->pkt_type != PACKET_HOST)
		goto discard_it;
#endif

	if (!pskb_may_pull(skb, sizeof(struct tcphdr))) {
                LOG_DBG("No TCP header\n");
                goto discard_it;
        }

	th = tcp_hdr(skb);

	if (th->doff < sizeof(struct tcphdr) / 4)
		goto bad_packet;

	if (!pskb_may_pull(skb, th->doff * 4))
		goto discard_it;

#if defined(OS_USER)
        /* FIXME: disable checksumming */
        skb->ip_summed = CHECKSUM_UNNECESSARY;
#endif
        /* An explanation is required here, I think.
	 * Packet length and doff are validated by header prediction,
	 * provided case of th->doff==0 is eliminated.
	 * So, we defer the checks. */
	if (!skb_csum_unnecessary(skb) && serval_tcp_v4_checksum_init(skb))
		goto bad_packet;

	iph = ip_hdr(skb);

	TCP_SKB_CB(skb)->seq = ntohl(th->seq);
	TCP_SKB_CB(skb)->end_seq = (TCP_SKB_CB(skb)->seq + th->syn + th->fin +
				    skb->len - th->doff * 4);
	TCP_SKB_CB(skb)->ack_seq = ntohl(th->ack_seq);
	TCP_SKB_CB(skb)->when	 = 0;
	TCP_SKB_CB(skb)->flags	 = iph->tos;
	TCP_SKB_CB(skb)->sacked	 = 0;
        
        LOG_PKT("TCP %s end_seq=%u doff=%u\n",
                tcphdr_to_str(th),
                TCP_SKB_CB(skb)->end_seq,
                th->doff * 4);

        if (!sock_owned_by_user(sk)) {
#ifdef CONFIG_NET_DMA        
                struct serval_tcp_sock *tp = serval_tcp_sk(sk);
                if (!tp->ucopy.dma_chan && tp->ucopy.pinned_list)
                        tp->ucopy.dma_chan = dma_find_channel(DMA_MEMCPY);
                if (tp->ucopy.dma_chan)
                        err = serval_tcp_do_rcv(sk, skb);
                else
#endif
                        {                
                                if (!serval_tcp_prequeue(sk, skb))
                                        err = serval_tcp_do_rcv(sk, skb);
                        }
        } else {
                /* We are processing the backlog in user/process
                   context */
                err = serval_tcp_do_rcv(sk, skb);
        }
        
        return err;
bad_packet:
        LOG_ERR("Bad TCP packet\n");
discard_it:
        LOG_ERR("Discarding TCP packet\n");
        kfree_skb(skb);

        return 0;
}

void serval_tcp_done(struct sock *sk)
{
        /*
	if (sk->sk_state == TCP_SYN_SENT || sk->sk_state == TCP_SYN_RECV)
		TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_ATTEMPTFAILS);
	//tcp_set_state(sk, TCP_CLOSE);

	sk->sk_shutdown = SHUTDOWN_MASK;

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_state_change(sk);
	else
		serval_sock_destroy(sk);
        */

	serval_tcp_clear_xmit_timers(sk);

        LOG_WARN("NOT implemented!\n");
}

static int serval_tcp_connection_close_request(struct sock *sk,
                                               struct sk_buff *skb)
{
        struct serval_tcp_sock *tp = serval_tcp_sk(sk);

        return tp->fin_recvd;
}

static int serval_tcp_connection_close(struct sock *sk)
{
        struct sk_buff *skb;
	int data_was_unread = 0;
        
	/*  We need to flush the recv. buffs.  We do this only on the
	 *  descriptor close, not protocol-sourced closes, because the
	 *  reader process may not have drained the data yet!
	 */
	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		u32 len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq -
			  tcp_hdr(skb)->fin;
		data_was_unread += len;
		__kfree_skb(skb);
	}

	sk_mem_reclaim(sk);
        
        LOG_DBG("Sending transport FIN\n");

        serval_tcp_send_fin(sk);

        return 0;
}

static unsigned int serval_tcp_xmit_size_goal(struct sock *sk, u32 mss_now,
                                              int large_allowed)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	u32 xmit_size_goal, old_size_goal;

	xmit_size_goal = mss_now;

	if (0 && large_allowed && sk_can_gso(sk)) {
		xmit_size_goal = ((sk->sk_gso_max_size - 1) -
				  SERVAL_NET_HEADER_LEN -
				  tp->tcp_header_len);

		xmit_size_goal = serval_tcp_bound_to_half_wnd(tp, xmit_size_goal);

		/* We try hard to avoid divides here */
		old_size_goal = tp->xmit_size_goal_segs * mss_now;

		if (likely(old_size_goal <= xmit_size_goal &&
			   old_size_goal + mss_now > xmit_size_goal)) {
			xmit_size_goal = old_size_goal;
		} else {
			tp->xmit_size_goal_segs = xmit_size_goal / mss_now;
			xmit_size_goal = tp->xmit_size_goal_segs * mss_now;
		}
	}

	return max(xmit_size_goal, mss_now);
}

static int serval_tcp_send_mss(struct sock *sk, int *size_goal, int flags)
{
	int mss_now;

	mss_now = serval_tcp_current_mss(sk);
	*size_goal = serval_tcp_xmit_size_goal(sk, mss_now, !(flags & MSG_OOB));

	return mss_now;
}

static inline void serval_tcp_mark_push(struct serval_tcp_sock *tp, 
                                 struct sk_buff *skb)
{
	TCP_SKB_CB(skb)->flags |= TCPH_PSH;
	tp->pushed_seq = tp->write_seq;
}

static inline int forced_push(struct serval_tcp_sock *tp)
{
	return after(tp->write_seq, tp->pushed_seq + (tp->max_window >> 1));
}

void serval_tcp_skb_free(struct sk_buff *skb)
{
        LOG_DBG("Freeing skb data packet, skb->len=%u\n", skb->len);
}

static inline void skb_serval_tcp_set_owner(struct sk_buff *skb, 
                                            struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = serval_tcp_skb_free;
        /* Guarantees the socket is not free'd for in-flight packets */
        //sock_hold(sk);
}

/* From net/ipv4/tcp.c */
struct sk_buff *sk_stream_alloc_skb(struct sock *sk, int size, gfp_t gfp)
{
	struct sk_buff *skb;

	/* The TCP header must be at least 32-bit aligned.  */
	size = ALIGN(size, 4);

	skb = alloc_skb(size + sk->sk_prot->max_header, gfp);

	if (skb) {
                LOG_DBG("Allocated skb size=%u skb->truesize=%u\n",
                        size + sk->sk_prot->max_header, skb->truesize);
                
                skb_serval_tcp_set_owner(skb, sk);

		if (sk_wmem_schedule(sk, skb->truesize)) {
			/*
			 * Make sure that we have exactly size bytes
			 * available to the caller, no more, no less.
			 */
			skb_reserve(skb, skb_tailroom(skb) - size);
			return skb;
		}
                LOG_ERR("sk_wmem_schedule=0\n");
		__kfree_skb(skb);
	} else {
		sk->sk_prot->enter_memory_pressure(sk);
                /* FIXME */
                LOG_WARN("Implement sk_stream_moderate_sndbuf()\n");
		/* sk_stream_moderate_sndbuf(sk); */
	}
	return NULL;
}

static inline void skb_entail(struct sock *sk, struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);

	skb->csum    = 0;
	tcb->seq     = tcb->end_seq = tp->write_seq;
	tcb->flags   = TCPH_ACK;
	tcb->sacked  = 0;
	skb_header_release(skb);
	serval_tcp_add_write_queue_tail(sk, skb);
	sk->sk_wmem_queued += skb->truesize;
	sk_mem_charge(sk, skb->truesize);
	if (tp->nonagle & TCP_NAGLE_PUSH)
		tp->nonagle &= ~TCP_NAGLE_PUSH;
}

#define TCP_PAGE(sk)	(sk->sk_sndmsg_page)
#define TCP_OFF(sk)	(sk->sk_sndmsg_off)

static inline int select_size(struct sock *sk, int sg)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int tmp = tp->mss_cache;

	if (sg) {
		if (0 && sk_can_gso(sk))
			tmp = 0;
		else {
			int pgbreak = SKB_MAX_HEAD(MAX_SERVAL_TCP_HEADER);

			if (tmp >= pgbreak &&
			    tmp <= pgbreak + (MAX_SKB_FRAGS - 1) * PAGE_SIZE)
				tmp = pgbreak;
		}
	}

	return tmp;
}

static inline void serval_tcp_mark_urg(struct serval_tcp_sock *tp, int flags)
{
	if (flags & MSG_OOB)
		tp->snd_up = tp->write_seq;        
}

static inline void serval_tcp_push(struct sock *sk, int flags, int mss_now,
                                   int nonagle)
{
	if (serval_tcp_send_head(sk)) {
		struct serval_tcp_sock *tp = serval_tcp_sk(sk);

		if (!(flags & MSG_MORE) || forced_push(tp))
			serval_tcp_mark_push(tp, serval_tcp_write_queue_tail(sk));

		serval_tcp_mark_urg(tp, flags);

                LOG_DBG("pushing pending frames\n");
		__serval_tcp_push_pending_frames(sk, mss_now,
                                                 (flags & MSG_MORE) ? 
                                                 TCP_NAGLE_CORK : nonagle);
	}
}

#ifdef CONFIG_NET_DMA
static void tcp_service_net_dma(struct sock *sk, bool wait)
{
	dma_cookie_t done, used;
	dma_cookie_t last_issued;
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tp->ucopy.dma_chan)
		return;

	last_issued = tp->ucopy.dma_cookie;
	dma_async_memcpy_issue_pending(tp->ucopy.dma_chan);

	do {
		if (dma_async_memcpy_complete(tp->ucopy.dma_chan,
					      last_issued, &done,
					      &used) == DMA_SUCCESS) {
			/* Safe to free early-copied skbs now */
			__skb_queue_purge(&sk->sk_async_wait_queue);
			break;
		} else {
			struct sk_buff *skb;
			while ((skb = skb_peek(&sk->sk_async_wait_queue)) &&
			       (dma_async_is_complete(skb->dma_cookie, done,
						      used) == DMA_SUCCESS)) {
				__skb_dequeue(&sk->sk_async_wait_queue);
				kfree_skb(skb);
			}
		}
	} while (wait);
}
#endif

#if defined(OS_LINUX_KERNEL)
/*
 *	Wait for a TCP event.
 *
 *	Note that we don't need to lock the socket, as the upper poll layers
 *	take care of normal races (between the test and the event) and we don't
 *	go look at any of the socket buffers directly.
 */
unsigned int serval_tcp_poll(struct file *file, 
                             struct socket *sock, 
                             poll_table *wait)
{
	unsigned int mask;
	struct sock *sk = sock->sk;
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	sock_poll_wait(file, sk_sleep(sk), wait);
        
        if (sk->sk_state == SERVAL_LISTEN) {
                struct serval_sock *ssk = serval_sk(sk);
                return list_empty(&ssk->accept_queue) ? 0 :
                        (POLLIN | POLLRDNORM);
        }

        /* Socket is not locked. We are protected from async events
	 * by poll logic and correct handling of state changes
	 * made by other threads is impossible in any case.
	 */

	mask = 0;

	/*
	 * POLLHUP is certainly not done right. But poll() doesn't
	 * have a notion of HUP in just one direction, and for a
	 * socket the read side is more interesting.
	 *
	 * Some poll() documentation says that POLLHUP is incompatible
	 * with the POLLOUT/POLLWR flags, so somebody should check this
	 * all. But careful, it tends to be safer to return too many
	 * bits than too few, and you can easily break real applications
	 * if you don't tell them that something has hung up!
	 *
	 * Check-me.
	 *
	 * Check number 1. POLLHUP is _UNMASKABLE_ event (see UNIX98 and
	 * our fs/select.c). It means that after we received EOF,
	 * poll always returns immediately, making impossible poll() on write()
	 * in state CLOSE_WAIT. One solution is evident --- to set POLLHUP
	 * if and only if shutdown has been made in both directions.
	 * Actually, it is interesting to look how Solaris and DUX
	 * solve this dilemma. I would prefer, if POLLHUP were maskable,
	 * then we could set it on SND_SHUTDOWN. BTW examples given
	 * in Stevens' books assume exactly this behaviour, it explains
	 * why POLLHUP is incompatible with POLLOUT.	--ANK
	 *
	 * NOTE. Check for TCP_CLOSE is added. The goal is to prevent
	 * blocking on fresh not-connected or disconnected socket. --ANK
	 */
	if (sk->sk_shutdown == SHUTDOWN_MASK || sk->sk_state == TCP_CLOSE)
		mask |= POLLHUP;
	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= POLLIN | POLLRDNORM | POLLRDHUP;

	/* Connected? */
	if ((1 << sk->sk_state) & ~(TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		int target = sock_rcvlowat(sk, 0, INT_MAX);

		if (tp->urg_seq == tp->copied_seq &&
		    !sock_flag(sk, SOCK_URGINLINE) &&
		    tp->urg_data)
			target++;

		/* Potential race condition. If read of tp below will
		 * escape above sk->sk_state, we can be illegally awaken
		 * in SYN_* states. */
		if (tp->rcv_nxt - tp->copied_seq >= target)
			mask |= POLLIN | POLLRDNORM;

		if (!(sk->sk_shutdown & SEND_SHUTDOWN)) {
			if (sk_stream_wspace(sk) >= sk_stream_min_wspace(sk)) {
				mask |= POLLOUT | POLLWRNORM;
			} else {  /* send SIGIO later */
				set_bit(SOCK_ASYNC_NOSPACE,
					&sk->sk_socket->flags);
				set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);

				/* Race breaker. If space is freed after
				 * wspace test but before the flags are set,
				 * IO signal will be lost.
				 */
				if (sk_stream_wspace(sk) >= sk_stream_min_wspace(sk))
					mask |= POLLOUT | POLLWRNORM;
			}
		} else
			mask |= POLLOUT | POLLWRNORM;

		if (tp->urg_data & TCP_URG_VALID)
			mask |= POLLPRI;
	}
	/* This barrier is coupled with smp_wmb() in tcp_reset() */
	smp_rmb();
	if (sk->sk_err)
		mask |= POLLERR;

	return mask;
}
#endif /* OS_LINUX_KERNEL */

static int serval_tcp_sendmsg(struct kiocb *iocb, struct sock *sk, 
                              struct msghdr *msg, size_t len)
{
	struct iovec *iov;
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *skb;
	int iovlen, flags;
	int mss_now, size_goal;
	int sg, err, copied;
	long timeo;

        LOG_DBG("Sending tcp message, len=%zu\n", len);

	lock_sock(sk);
	TCP_CHECK_TIMER(sk);

	flags = msg->msg_flags;
	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	/* Wait for a connection to finish. */
	if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
		if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)
			goto out_err;

	/* This should be in poll */
	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	mss_now = serval_tcp_send_mss(sk, &size_goal, flags);

	/* Ok commence sending. */
	iovlen = msg->msg_iovlen;
	iov = msg->msg_iov;
	copied = 0;

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto out_err;

        /* Check scatter/gather I/O capability */
	sg = sk->sk_route_caps & NETIF_F_SG;

	while (--iovlen >= 0) {
		int seglen = iov->iov_len;
		char *from = iov->iov_base;

		iov++;

		while (seglen > 0) {
			int copy = 0;
			int max = size_goal;

			skb = serval_tcp_write_queue_tail(sk);

			if (serval_tcp_send_head(sk)) {
				if (skb->ip_summed == CHECKSUM_NONE)
					max = mss_now;
				copy = max - skb->len;
			}

			if (copy <= 0) {
#if defined(OS_LINUX_KERNEL)
new_segment:
#endif
				/* Allocate new segment. If the interface is SG,
				 * allocate skb fitting to single page.
				 */
				if (!sk_stream_memory_free(sk))
					goto wait_for_sndbuf;

                                LOG_DBG("Allocating skb size=%d\n", 
                                        select_size(sk, sg));

				skb = sk_stream_alloc_skb(sk,
							  select_size(sk, sg),
							  sk->sk_allocation);
				if (!skb)
					goto wait_for_memory;

				/*
				 * Check whether we can use HW checksum.
				 */
				//if (sk->sk_route_caps & NETIF_F_ALL_CSUM)
				//	skb->ip_summed = CHECKSUM_PARTIAL;
                                skb->ip_summed = CHECKSUM_NONE;

				skb_entail(sk, skb);
				copy = size_goal;
				max = size_goal;
			}

                        LOG_DBG("copy=%u seglen=%u\n",
                                copy, seglen);

			/* Try to append data to the end of skb. */
			if (copy > seglen)
				copy = seglen;

			/* Where to copy to? */
			if (skb_tailroom(skb) > 0) {
				/* We have some space in skb head. Superb! */
				if (copy > skb_tailroom(skb))
					copy = skb_tailroom(skb);

                                LOG_DBG("Add data tailroom=%u copy=%u\n", 
                                        skb_tailroom(skb), copy);
                                
				if ((err = skb_add_data(skb, from, copy)) != 0) {
                                        LOG_ERR("skb_add_data() failed!\n");
					goto do_fault;
                                }
			} else {
#if defined(ENABLE_PAGE)
				int merge = 0;
				int i = skb_shinfo(skb)->nr_frags;
				struct page *page = TCP_PAGE(sk);
				int off = TCP_OFF(sk);

				if (skb_can_coalesce(skb, i, page, off) &&
				    off != PAGE_SIZE) {
					/* We can extend the last page
					 * fragment. */
					merge = 1;
				} else if (i == MAX_SKB_FRAGS || !sg) {
					/* Need to add new fragment and cannot
					 * do this because interface is non-SG,
					 * or because all the page slots are
					 * busy. */
					serval_tcp_mark_push(tp, skb);
					goto new_segment;
				} else if (page) {
					if (off == PAGE_SIZE) {
						put_page(page);
						TCP_PAGE(sk) = page = NULL;
						off = 0;
					}
				} else
					off = 0;

				if (copy > PAGE_SIZE - off)
					copy = PAGE_SIZE - off;

				if (!sk_wmem_schedule(sk, copy))
					goto wait_for_memory;

				if (!page) {
					/* Allocate new cache page. */
					if (!(page = sk_stream_alloc_page(sk)))
						goto wait_for_memory;
				}

				/* Time to copy data. We are close to
				 * the end! */
				err = skb_copy_to_page(sk, from, skb, page,
						       off, copy);
				if (err) {
					/* If this page was new, give it to the
					 * socket so it does not get leaked.
					 */
					if (!TCP_PAGE(sk)) {
						TCP_PAGE(sk) = page;
						TCP_OFF(sk) = 0;
					}
					goto do_error;
				}

				/* Update the skb. */
				if (merge) {
					skb_shinfo(skb)->frags[i - 1].size +=
									copy;
				} else {
					skb_fill_page_desc(skb, i, page, off, copy);
					if (TCP_PAGE(sk)) {
						get_page(page);
					} else if (off + copy < PAGE_SIZE) {
						get_page(page);
						TCP_PAGE(sk) = page;
					}
				}

				TCP_OFF(sk) = off + copy;
#endif /* ENABLE_PAGE */
                                LOG_DBG("No tailroom in skb, add page\n");
			}

			if (!copied)
				TCP_SKB_CB(skb)->flags &= ~TCPH_PSH;

			tp->write_seq += copy;
			TCP_SKB_CB(skb)->end_seq += copy;
			skb_shinfo(skb)->gso_segs = 0;

			from += copy;
			copied += copy;
			if ((seglen -= copy) == 0 && iovlen == 0)
				goto out;

			if (skb->len < max || (flags & MSG_OOB))
				continue;

                        LOG_DBG("skb->len=%u max=%u\n", skb->len, max);

			if (forced_push(tp)) {
				serval_tcp_mark_push(tp, skb);
				__serval_tcp_push_pending_frames(sk, 
                                                                 mss_now, 
                                                                 TCP_NAGLE_PUSH);
			} else if (skb == serval_tcp_send_head(sk))
				serval_tcp_push_one(sk, mss_now);
			continue;

wait_for_sndbuf:
			set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
			if (copied)
				serval_tcp_push(sk, flags & ~MSG_MORE, 
                                                mss_now, TCP_NAGLE_PUSH);
                        
                        if ((err = sk_stream_wait_memory(sk, &timeo)) != 0)
				goto do_error;

			mss_now = serval_tcp_send_mss(sk, &size_goal, flags);
		}
	}

out:
	if (copied)
		serval_tcp_push(sk, flags, mss_now, tp->nonagle);
	TCP_CHECK_TIMER(sk);
	release_sock(sk);

        LOG_DBG("Total copied=%u\n", copied);

	return copied;

do_fault:
	if (!skb->len) {
		serval_tcp_unlink_write_queue(skb, sk);
		/* It is the one place in all of TCP, except connection
		 * reset, where we can be unlinking the send_head.
		 */
		serval_tcp_check_send_head(sk, skb);
		sk_wmem_free_skb(sk, skb);
	}

do_error:
	if (copied)
		goto out;
out_err:
	err = sk_stream_error(sk, flags, err);

        LOG_ERR("error=%d\n", err);

	TCP_CHECK_TIMER(sk);
	release_sock(sk);
	return err;
}

/*
 *	Handle reading urgent data. BSD has very simple semantics for
 *	this, no blocking and very strange errors 8)
 */

static int serval_tcp_recv_urg(struct sock *sk, struct msghdr *msg, 
                               int len, int flags)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	/* No URG data to read. */
	if (sock_flag(sk, SOCK_URGINLINE) || !tp->urg_data ||
	    tp->urg_data == TCP_URG_READ)
		return -EINVAL;	/* Yes this is right ! */

	if (sk->sk_state == TCP_CLOSE && !sock_flag(sk, SOCK_DONE))
		return -ENOTCONN;

	if (tp->urg_data & TCP_URG_VALID) {
		int err = 0;
		unsigned char c = tp->urg_data;

		if (!(flags & MSG_PEEK))
			tp->urg_data = TCP_URG_READ;

		/* Read urgent data. */
		msg->msg_flags |= MSG_OOB;

		if (len > 0) {
			if (!(flags & MSG_TRUNC))
				err = memcpy_toiovec(msg->msg_iov, &c, 1);
			len = 1;
		} else
			msg->msg_flags |= MSG_TRUNC;

		return err ? -EFAULT : len;
	}

	if (sk->sk_state == TCP_CLOSE || (sk->sk_shutdown & RCV_SHUTDOWN))
		return 0;

	/* Fixed the recv(..., MSG_OOB) behaviour.  BSD docs and
	 * the available implementations agree in this case:
	 * this call should never block, independent of the
	 * blocking state of the socket.
	 * Mike <pall@rz.uni-karlsruhe.de>
	 */
	return -EAGAIN;
}

/* Clean up the receive buffer for full frames taken by the user,
 * then send an ACK if necessary.  COPIED is the number of bytes
 * tcp_recvmsg has given to the user so far, it speeds up the
 * calculation of whether or not we must ACK for the sake of
 * a window update.
 */
void serval_tcp_cleanup_rbuf(struct sock *sk, int copied)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int time_to_ack = 0;

#if TCP_DEBUG
        /*
	struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);
	WARN(skb && !before(tp->copied_seq, TCP_SKB_CB(skb)->end_seq),
	     KERN_INFO "cleanup rbuf bug: copied %X seq %X rcvnxt %X\n",
	     tp->copied_seq, TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt);
        */
#endif
	if (serval_tsk_ack_scheduled(sk)) {
		   /* Delayed ACKs frequently hit locked sockets during bulk
		    * receive. */
		if (tp->tp_ack.blocked ||
		    /* Once-per-two-segments ACK was not sent by tcp_input.c */
		    tp->rcv_nxt - tp->rcv_wup > tp->tp_ack.rcv_mss ||
		    /*
		     * If this read emptied read buffer, we send ACK, if
		     * connection is not bidirectional, user drained
		     * receive buffer and there was a small segment
		     * in queue.
		     */
		    (copied > 0 &&
		     ((tp->tp_ack.pending & STSK_ACK_PUSHED2) ||
		      ((tp->tp_ack.pending & STSK_ACK_PUSHED) &&
		       !tp->tp_ack.pingpong)) &&
		      !atomic_read(&sk->sk_rmem_alloc)))
			time_to_ack = 1;
	}
	/* We send an ACK if we can now advertise a non-zero window
	 * which has been raised "significantly".
	 *
	 * Even if window raised up to infinity, do not send window open ACK
	 * in states, where we will not receive more. It is useless.
	 */
	if (copied > 0 && !time_to_ack && !(sk->sk_shutdown & RCV_SHUTDOWN)) {
		__u32 rcv_window_now = serval_tcp_receive_window(tp);

		/* Optimize, __tcp_select_window() is not cheap. */
		if (2*rcv_window_now <= tp->window_clamp) {
			__u32 new_window = __serval_tcp_select_window(sk);

			/* Send ACK now, if this read freed lots of space
			 * in our buffer. Certainly, new_window is new window.
			 * We can advertise it now, if it is not less than current one.
			 * "Lots" means "at least twice" here.
			 */
			if (new_window && new_window >= 2 * rcv_window_now)
				time_to_ack = 1;
		}
	}

	if (time_to_ack)
		serval_tcp_send_ack(sk);
}

static void serval_tcp_prequeue_process(struct sock *sk)
{
	struct sk_buff *skb;
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	//NET_INC_STATS_USER(sock_net(sk), LINUX_MIB_TCPPREQUEUED);

	/* RX process wants to run with disabled BHs, though it is not
	 * necessary */
	local_bh_disable();
	while ((skb = __skb_dequeue(&tp->ucopy.prequeue)) != NULL)
                /* We cannot call sk_backlog_rcv here as we do backlog
                   queueing and processing in the SAL, and therefore
                   sk_backlog_rcv will put the packet back in SAL and
                   then through TCP processing again (part of which we
                   have already done at this point.

                   We must instead call serval_tcp_do_rcv directly
                   since that is the logical next step in the packet
                   processing. 
                */
		/* sk_backlog_rcv(sk, skb); */
                serval_tcp_do_rcv(sk, skb);

	local_bh_enable();

	/* Clear memory counter. */
	tp->ucopy.memory = 0;
}

static int serval_tcp_recvmsg(struct kiocb *iocb, struct sock *sk, 
                              struct msghdr *msg,
                              size_t len, int nonblock, int flags, 
                              int *addr_len)
{
 	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int copied = 0;
	u32 peek_seq;
	u32 *seq;
	unsigned long used;
	int err;
	int target;		/* Read at least this many bytes */
	long timeo;
	struct task_struct *user_recv = NULL;
	int copied_early = 0;
	struct sk_buff *skb;
	u32 urg_hole = 0;

        LOG_DBG("User reads data len=%zu\n", len);

	lock_sock(sk);

	TCP_CHECK_TIMER(sk);

	err = -ENOTCONN;
	if (sk->sk_state == TCP_LISTEN)
		goto out;

	timeo = sock_rcvtimeo(sk, nonblock);

	/* Urgent data needs to be handled specially. */
	if (flags & MSG_OOB)
		goto recv_urg;

	seq = &tp->copied_seq;
	if (flags & MSG_PEEK) {
		peek_seq = tp->copied_seq;
		seq = &peek_seq;
	}

	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);

#ifdef CONFIG_NET_DMA
	tp->ucopy.dma_chan = NULL;
	preempt_disable();
	skb = skb_peek_tail(&sk->sk_receive_queue);
	{
		int available = 0;

		if (skb)
			available = TCP_SKB_CB(skb)->seq + skb->len - (*seq);
		if ((available < target) &&
		    (len > sysctl_tcp_dma_copybreak) && !(flags & MSG_PEEK) &&
		    !sysctl_serval_tcp_low_latency &&
		    dma_find_channel(DMA_MEMCPY)) {
			preempt_enable_no_resched();
			tp->ucopy.pinned_list =
					dma_pin_iovec_pages(msg->msg_iov, len);
		} else {
			preempt_enable_no_resched();
		}
	}
#endif

	do {
		u32 offset;

		/* Are we at urgent data? Stop if we have read
                 * anything or have SIGURG pending. */
		if (tp->urg_data && tp->urg_seq == *seq) {
			if (copied)
				break;
			if (signal_pending(current)) {
				copied = timeo ? sock_intr_errno(timeo) : 
                                        -EAGAIN;
				break;
			}
		}

		/* Next get a buffer. */

		skb_queue_walk(&sk->sk_receive_queue, skb) {
			/* Now that we have two receive queues this
			 * shouldn't happen.
			 */

			if (before(*seq, TCP_SKB_CB(skb)->seq))
				break;

			offset = *seq - TCP_SKB_CB(skb)->seq;
			if (tcp_hdr(skb)->syn)
				offset--;
			if (offset < skb->len)
				goto found_ok_skb;
			if (tcp_hdr(skb)->fin)
				goto found_fin_ok;
                                 /*
			WARN(!(flags & MSG_PEEK), KERN_INFO "recvmsg bug 2: "
					"copied %X seq %X rcvnxt %X fl %X\n",
					*seq, TCP_SKB_CB(skb)->seq,
					tp->rcv_nxt, flags);
                                 */
		}

		/* Well, if we have backlog, try to process it now yet. */

		if (copied >= target && !sk->sk_backlog.tail)
			break;

		if (copied) {
			if (sk->sk_err ||
			    sk->sk_state == TCP_CLOSE ||
			    (sk->sk_shutdown & RCV_SHUTDOWN) ||
			    !timeo ||
			    signal_pending(current))
				break;
		} else {
			if (sock_flag(sk, SOCK_DONE))
				break;

			if (sk->sk_err) {
				copied = sock_error(sk);
				break;
			}

			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;

			if (sk->sk_state == TCP_CLOSE) {
				if (!sock_flag(sk, SOCK_DONE)) {
					/* This occurs when user tries to read
					 * from never connected socket.
					 */
					copied = -ENOTCONN;
					break;
				}
				break;
			}

			if (!timeo) {
				copied = -EAGAIN;
				break;
			}

			if (signal_pending(current)) {
				copied = sock_intr_errno(timeo);
				break;
			}
		}

		serval_tcp_cleanup_rbuf(sk, copied);

		if (!sysctl_serval_tcp_low_latency && tp->ucopy.task == user_recv) {
			/* Install new reader */
			if (!user_recv && !(flags & (MSG_TRUNC | MSG_PEEK))) {
				user_recv = current;
				tp->ucopy.task = user_recv;
				tp->ucopy.iov = msg->msg_iov;
			}

			tp->ucopy.len = len;

			WARN_ON(tp->copied_seq != tp->rcv_nxt &&
				!(flags & (MSG_PEEK | MSG_TRUNC)));

			/* Ugly... If prequeue is not empty, we have to
			 * process it before releasing socket, otherwise
			 * order will be broken at second iteration.
			 * More elegant solution is required!!!
			 *
			 * Look: we have the following (pseudo)queues:
			 *
			 * 1. packets in flight
			 * 2. backlog
			 * 3. prequeue
			 * 4. receive_queue
			 *
			 * Each queue can be processed only if the next ones
			 * are empty. At this point we have empty receive_queue.
			 * But prequeue _can_ be not empty after 2nd iteration,
			 * when we jumped to start of loop because backlog
			 * processing added something to receive_queue.
			 * We cannot release_sock(), because backlog contains
			 * packets arrived _after_ prequeued ones.
			 *
			 * Shortly, algorithm is clear --- to process all
			 * the queues in order. We could make it more directly,
			 * requeueing packets from backlog to prequeue, if
			 * is not empty. It is more elegant, but eats cycles,
			 * unfortunately.
			 */
			if (!skb_queue_empty(&tp->ucopy.prequeue))
				goto do_prequeue;

			/* __ Set realtime policy in scheduler __ */
		}

#ifdef CONFIG_NET_DMA
		if (tp->ucopy.dma_chan)
			dma_async_memcpy_issue_pending(tp->ucopy.dma_chan);
#endif
		if (copied >= target) {
			/* Do not sleep, just process backlog. */
			release_sock(sk);
			lock_sock(sk);
		} else
			sk_wait_data(sk, &timeo);

#ifdef CONFIG_NET_DMA
		tcp_service_net_dma(sk, false);  /* Don't block */
		tp->ucopy.wakeup = 0;
#endif

		if (user_recv) {
			int chunk;

			/* __ Restore normal policy in scheduler __ */

			if ((chunk = len - tp->ucopy.len) != 0) {
                                /*
				NET_ADD_STATS_USER(sock_net(sk), 
                                                   LINUX_MIB_TCPDIRECTCOPYFROMBACKLOG, chunk);
                                */
				len -= chunk;
				copied += chunk;
			}

			if (tp->rcv_nxt == tp->copied_seq &&
			    !skb_queue_empty(&tp->ucopy.prequeue)) {
do_prequeue:
				serval_tcp_prequeue_process(sk);

				if ((chunk = len - tp->ucopy.len) != 0) {
                                        /*
					NET_ADD_STATS_USER(sock_net(sk), LINUX_MIB_TCPDIRECTCOPYFROMPREQUEUE, chunk);
                                        */
					len -= chunk;
					copied += chunk;
				}
			}
		}
		if ((flags & MSG_PEEK) &&
		    (peek_seq - copied - urg_hole != tp->copied_seq)) {
			if (net_ratelimit())
				/* 
                                   printk(KERN_DEBUG "TCP(%s:%d): Application bug, race in MSG_PEEK.\n",
				       current->comm, task_pid_nr(current));
                                */
			peek_seq = tp->copied_seq;
		}
		continue;

	found_ok_skb:
		/* Ok so how much can we use? */
		used = skb->len - offset;
		if (len < used)
			used = len;

		/* Do we have urgent data here? */
		if (tp->urg_data) {
			u32 urg_offset = tp->urg_seq - *seq;
			if (urg_offset < used) {
				if (!urg_offset) {
					if (!sock_flag(sk, SOCK_URGINLINE)) {
						++*seq;
						urg_hole++;
						offset++;
						used--;
						if (!used)
							goto skip_copy;
					}
				} else
					used = urg_offset;
			}
		}

		if (!(flags & MSG_TRUNC)) {
#ifdef CONFIG_NET_DMA
			if (!tp->ucopy.dma_chan && tp->ucopy.pinned_list)
				tp->ucopy.dma_chan = 
                                        dma_find_channel(DMA_MEMCPY);

			if (tp->ucopy.dma_chan) {
				tp->ucopy.dma_cookie = 
                                        dma_skb_copy_datagram_iovec(
                                                tp->ucopy.dma_chan, skb, 
                                                offset,
                                                msg->msg_iov, used,
                                                tp->ucopy.pinned_list);
                                
				if (tp->ucopy.dma_cookie < 0) {

					printk(KERN_ALERT "dma_cookie < 0\n");

					/* Exception. Bailout! */
					if (!copied)
						copied = -EFAULT;
					break;
				}

				dma_async_memcpy_issue_pending(tp->ucopy.dma_chan);

				if ((offset + used) == skb->len)
					copied_early = 1;

			} else
#endif
			{
				err = skb_copy_datagram_iovec(skb, offset,
						msg->msg_iov, used);
				if (err) {
					/* Exception. Bailout! */
					if (!copied)
						copied = -EFAULT;
					break;
				}
			}
		}

		*seq += used;
		copied += used;
		len -= used;

		serval_tcp_rcv_space_adjust(sk);

skip_copy:
		if (tp->urg_data && after(tp->copied_seq, tp->urg_seq)) {
			tp->urg_data = 0;
			serval_tcp_fast_path_check(sk);
		}
		if (used + offset < skb->len)
			continue;

		if (tcp_hdr(skb)->fin)
			goto found_fin_ok;
		if (!(flags & MSG_PEEK)) {
			sk_eat_skb(sk, skb, copied_early);
			copied_early = 0;
		}
		continue;

	found_fin_ok:
		/* Process the FIN. */
                LOG_DBG("processing FIN\n");
		++*seq;
		if (!(flags & MSG_PEEK)) {
			sk_eat_skb(sk, skb, copied_early);
			copied_early = 0;
		}
		break;
	} while (len > 0);

	if (user_recv) {
		if (!skb_queue_empty(&tp->ucopy.prequeue)) {
			int chunk;

			tp->ucopy.len = copied > 0 ? len : 0;

			serval_tcp_prequeue_process(sk);

			if (copied > 0 && (chunk = len - tp->ucopy.len) != 0) {
				/*
                                  NET_ADD_STATS_USER(sock_net(sk), 
                                  LINUX_MIB_TCPDIRECTCOPYFROMPREQUEUE, chunk);
                                */
				len -= chunk;
				copied += chunk;
			}
		}

		tp->ucopy.task = NULL;
		tp->ucopy.len = 0;
	}

#ifdef CONFIG_NET_DMA
	tcp_service_net_dma(sk, true);  /* Wait for queue to drain */
	tp->ucopy.dma_chan = NULL;

	if (tp->ucopy.pinned_list) {
		dma_unpin_iovec_pages(tp->ucopy.pinned_list);
		tp->ucopy.pinned_list = NULL;
	}
#endif

	/* According to UNIX98, msg_name/msg_namelen are ignored
	 * on connected socket. I was just happy when found this 8) --ANK
	 */

	/* Clean up data we have read: This will do ACK frames. */
        LOG_DBG("Copied %d bytes\n", copied);
	serval_tcp_cleanup_rbuf(sk, copied);

	TCP_CHECK_TIMER(sk);
	release_sock(sk);
	return copied;

out:
	TCP_CHECK_TIMER(sk);
	release_sock(sk);
	return err;

recv_urg:
	err = serval_tcp_recv_urg(sk, msg, len, flags);
	goto out;
}

static void __serval_tcp_v4_send_check(struct sk_buff *skb,
                                       __be32 saddr, __be32 daddr)
{
	struct tcphdr *th = tcp_hdr(skb);

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		th->check = ~serval_tcp_v4_check(skb->len, saddr, daddr, 0);
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		th->check = serval_tcp_v4_check(skb->len, saddr, daddr,
                                                csum_partial(th,
                                                             th->doff << 2,
                                                             skb->csum));
	}
}

/* This routine computes an IPv4 TCP checksum. */
void serval_tcp_v4_send_check(struct sock *sk, struct sk_buff *skb)
{
	struct inet_sock *inet = inet_sk(sk);

	__serval_tcp_v4_send_check(skb, inet->inet_saddr, inet->inet_daddr);
}

static struct serval_sock_af_ops serval_tcp_af_ops = {
        .queue_xmit = serval_ipv4_xmit_skb,
        .receive = serval_tcp_rcv,
        .send_check = serval_tcp_v4_send_check,
        .conn_build_syn = serval_tcp_connection_build_syn,
        .conn_build_synack = serval_tcp_connection_build_synack,
        .conn_build_ack = serval_tcp_connection_build_ack,
        .conn_build_fin = serval_tcp_connection_build_fin,
        .conn_request = serval_tcp_connection_request,
        .conn_close = serval_tcp_connection_close,
        .close_request = serval_tcp_connection_close_request,
        .request_state_process = serval_tcp_syn_sent_state_process,
        .respond_state_process = serval_tcp_syn_recv_state_process,
        .conn_child_sock = serval_tcp_connection_respond_sock,
        .recv_fin = serval_sal_rcv_transport_fin,
};

/**
   Called when a child sock is created in response to a successful
   three-way handshake on the server side.
 */
int serval_tcp_connection_respond_sock(struct sock *sk, 
                                       struct sk_buff *skb,
                                       struct request_sock *req,
                                       struct sock *newsk,
                                       struct dst_entry *dst)
{
        //struct serval_sock *new_ssk = serval_sk(newsk);
        //struct inet_sock *newinet = inet_sk(newsk);
        struct inet_request_sock *ireq = inet_rsk(req);
        struct serval_tcp_sock *newtp = serval_tcp_sk(newsk);
        struct serval_tcp_sock *oldtp = serval_tcp_sk(sk);
        struct serval_tcp_request_sock *treq = serval_tcp_rsk(req);

        LOG_DBG("New TCP sock based on pkt %s\n", 
                tcphdr_to_str(tcp_hdr(skb)));

#if defined(OS_LINUX_KERNEL)
        /* Must make sure we have a route */
	if (!dst && (dst = serval_sock_route_req(sk, req)) == NULL)
		goto exit;
#endif

	newtp->pred_flags = 0;

        newtp->rcv_wup = newtp->copied_seq =
                newtp->rcv_nxt = treq->rcv_isn + 1;

        newtp->snd_sml = newtp->snd_una =
		newtp->snd_nxt = newtp->snd_up =
                treq->snt_isn + 1 + serval_tcp_s_data_size(oldtp);

        serval_tcp_prequeue_init(newtp);

        serval_tcp_init_wl(newtp, treq->rcv_isn);

        newtp->srtt = 0;
        newtp->mdev = SERVAL_TCP_TIMEOUT_INIT;
        newtp->rto = SERVAL_TCP_TIMEOUT_INIT;

        newtp->packets_out = 0;
        newtp->retrans_out = 0;
        newtp->sacked_out = 0;
        newtp->fackets_out = 0;
        newtp->snd_ssthresh = SERVAL_TCP_INFINITE_SSTHRESH;

        /* So many TCP implementations out there (incorrectly) count the
         * initial SYN frame in their delayed-ACK and congestion control
         * algorithms that we must have the following bandaid to talk
         * efficiently to them.  -DaveM
         */
        newtp->snd_cwnd = 2;
        newtp->snd_cwnd_cnt = 0;
        newtp->bytes_acked = 0;

        newtp->frto_counter = 0;
        newtp->frto_highmark = 0;

        newtp->ca_ops = &serval_tcp_init_congestion_ops;

        serval_tcp_set_ca_state(newsk, TCP_CA_Open);
        serval_tcp_init_xmit_timers(newsk);
        skb_queue_head_init(&newtp->out_of_order_queue);
        newtp->write_seq = newtp->pushed_seq =
                treq->snt_isn + 1 + serval_tcp_s_data_size(oldtp);

        newtp->rx_opt.saw_tstamp = 0;

        newtp->rx_opt.dsack = 0;
        newtp->rx_opt.num_sacks = 0;

        newtp->urg_data = 0;

        /*
          if (sock_flag(newsk, SOCK_KEEPOPEN))
          inet_csk_reset_keepalive_timer(newsk,
          keepalive_time_when(newtp));
        */
        newtp->rx_opt.tstamp_ok = ireq->tstamp_ok;
        /*
          if ((newtp->rx_opt.sack_ok = ireq->sack_ok) != 0) {
          if (sysctl_tcp_fack)
          tcp_enable_fack(newtp);
          }
        */
        newtp->window_clamp = req->window_clamp;
        newtp->rcv_ssthresh = req->rcv_wnd;
        newtp->rcv_wnd = req->rcv_wnd;
        newtp->rx_opt.wscale_ok = treq->wscale_ok;

        if (newtp->rx_opt.wscale_ok) {
                newtp->rx_opt.snd_wscale = ireq->snd_wscale;
                newtp->rx_opt.rcv_wscale = ireq->rcv_wscale;
        } else {
                LOG_DBG("No TCP window scaling!\n");
                newtp->rx_opt.snd_wscale = newtp->rx_opt.rcv_wscale = 0;
                newtp->window_clamp = min(newtp->window_clamp, 65535U);
        }
        newtp->snd_wnd = (ntohs(tcp_hdr(skb)->window) <<
                          newtp->rx_opt.snd_wscale);

        newtp->max_window = newtp->snd_wnd;
        
        LOG_DBG("snd_wnd=%u rcv_wnd=%u rcv_nxt=%u snd_nxt=%u snt_isn\n", 
                newtp->snd_wnd, newtp->rcv_wnd, 
                newtp->rcv_nxt, newtp->snd_nxt, 
                treq->snt_isn);
                
        if (newtp->rx_opt.tstamp_ok ) {
                  newtp->rx_opt.ts_recent = req->ts_recent;
                  newtp->rx_opt.ts_recent_stamp = get_seconds();
                  newtp->tcp_header_len = sizeof(struct tcphdr) + 
                          TCPOLEN_TSTAMP_ALIGNED;
        } else {
                newtp->rx_opt.ts_recent_stamp = 0;
                newtp->tcp_header_len = sizeof(struct tcphdr);
        }
        
        if (skb->len >= SERVAL_TCP_MSS_DEFAULT + newtp->tcp_header_len)
                newtp->tp_ack.last_seg_size = skb->len - newtp->tcp_header_len;

        
        newtp->rx_opt.mss_clamp = req->mss;

	newsk->sk_gso_type = 0; //SKB_GSO_TCPV4;
	sk_setup_caps(newsk, dst);
	
	//newinet->inet_id = newtp->write_seq ^ jiffies;

	serval_tcp_mtup_init(newsk);
#if defined(OS_LINUX_KERNEL)
        serval_tcp_sync_mss(newsk, dst_mtu(dst));
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37))
	newtp->advmss = dst_metric(dst, RTAX_ADVMSS);
#else
        newtp->advmss = dst_metric_advmss(dst);
#endif
#else
        serval_tcp_sync_mss(newsk, SERVAL_TCP_MSS_DEFAULT);
	newtp->advmss = SERVAL_TCP_MSS_DEFAULT;
#endif

	if (serval_tcp_sk(sk)->rx_opt.user_mss &&
	    serval_tcp_sk(sk)->rx_opt.user_mss < newtp->advmss)
		newtp->advmss = serval_tcp_sk(sk)->rx_opt.user_mss;

	serval_tcp_initialize_rcv_mss(newsk);

        newtp->bytes_queued = 0;

        return 0;
#if defined(OS_LINUX_KERNEL)
exit:
        dst_release(dst);
        return -1;
#endif
}

static int serval_tcp_init_sock(struct sock *sk)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_tcp_sock *tp = serval_tcp_sk(sk);

        LOG_DBG("Initializing new TCP sock\n");

        skb_queue_head_init(&tp->out_of_order_queue);
	serval_tcp_init_xmit_timers(sk);
	serval_tcp_prequeue_init(tp);

        tp->rto = SERVAL_TCP_TIMEOUT_INIT;
	tp->mdev = SERVAL_TCP_TIMEOUT_INIT;
        /* So many TCP implementations out there (incorrectly) count
	 * the initial SYN frame in their delayed-ACK and congestion
	 * control algorithms that we must have the following bandaid
	 * to talk efficiently to them.  -DaveM
	 */
	tp->snd_cwnd = 2;

	/* See draft-stevens-tcpca-spec-01 for discussion of the
	 * initialization of these values.
	 */
	tp->snd_ssthresh = SERVAL_TCP_INFINITE_SSTHRESH;
	tp->snd_cwnd_clamp = ~0;
	tp->mss_cache = SERVAL_TCP_MSS_DEFAULT;

	tp->reordering = sysctl_serval_tcp_reordering;

	/* So many TCP implementations out there (incorrectly) count the
	 * initial SYN frame in their delayed-ACK and congestion control
	 * algorithms that we must have the following bandaid to talk
	 * efficiently to them.  -DaveM
	 */
	tp->snd_cwnd = 2;
	tp->ca_ops = &serval_tcp_init_congestion_ops;

	sk->sk_write_space = sk_stream_write_space;
	sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

        ssk->af_ops = &serval_tcp_af_ops;

	sk->sk_sndbuf = sysctl_tcp_wmem[1];
	sk->sk_rcvbuf = sysctl_tcp_rmem[1];

        tp->bytes_queued = 0;

#if defined(OS_LINUX_KERNEL)
	local_bh_disable();
	percpu_counter_inc(&tcp_sockets_allocated);
	local_bh_enable();
#endif
        return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
static int serval_tcp_destroy_sock(struct sock *sk)
#else
static void serval_tcp_destroy_sock(struct sock *sk)
#endif
{
        struct serval_tcp_sock *tp = serval_tcp_sk(sk);
   
        LOG_DBG("destroying TCP sock\n");

	serval_tcp_clear_xmit_timers(sk);

	serval_tcp_cleanup_congestion_control(sk);

	/* Cleanup up the write buffer. */
	serval_tcp_write_queue_purge(sk);

	__skb_queue_purge(&tp->out_of_order_queue);

#ifdef CONFIG_NET_DMA
	/* Cleans up our sk_async_wait_queue */
	__skb_queue_purge(&sk->sk_async_wait_queue);
#endif
        
	/* Clean prequeue, it must be empty really */
	__skb_queue_purge(&tp->ucopy.prequeue);

#if defined(OS_LINUX_KERNEL)
	if (sk->sk_sndmsg_page) {
		__free_page(sk->sk_sndmsg_page);
		sk->sk_sndmsg_page = NULL;
	}
#endif
        
	//percpu_counter_dec(&tcp_sockets_allocated);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
        return 0;
#endif
}

static void serval_tcp_request_sock_destructor(struct request_sock *req)
{
}

struct request_sock_ops tcp_request_sock_ops __read_mostly = {
	.family		=	PF_INET,
	.obj_size	=	sizeof(struct serval_tcp_request_sock),
        .destructor     =       serval_tcp_request_sock_destructor,
};

struct proto serval_tcp_proto = {
	.name			= "SERVAL_TCP",
	.owner			= THIS_MODULE,
        .init                   = serval_tcp_init_sock,
        .destroy                = serval_tcp_destroy_sock,
	.close  		= serval_sal_close,   
        .connect                = serval_sal_connect,
	.disconnect		= serval_tcp_disconnect,
	.shutdown		= serval_tcp_shutdown,
        .sendmsg                = serval_tcp_sendmsg,
        .recvmsg                = serval_tcp_recvmsg,
	.backlog_rcv		= serval_sal_do_rcv,
        .hash                   = serval_sock_hash,
        .unhash                 = serval_sock_unhash,
	.enter_memory_pressure	= tcp_enter_memory_pressure,
	.memory_pressure	= &tcp_memory_pressure,
	.memory_allocated	= &serval_tcp_memory_allocated,
	.sysctl_mem		= sysctl_tcp_mem,
	.sysctl_wmem		= sysctl_tcp_wmem,
	.sysctl_rmem		= sysctl_tcp_rmem,
#if defined(OS_LINUX_KERNEL)
	.sockets_allocated	= &tcp_sockets_allocated,
	.orphan_count		= &tcp_orphan_count,
#endif
	.max_header		= MAX_SERVAL_TCP_HEADER,
	.obj_size		= sizeof(struct serval_tcp_sock),
	.rsk_prot		= &tcp_request_sock_ops,
};
