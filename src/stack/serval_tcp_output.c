/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/netdevice.h>
#include <serval/debug.h>
#include <serval_tcp.h>
#include <serval_request_sock.h>
#include <serval_tcp_request_sock.h>
#if defined(OS_USER)
#include <userlevel/serval_tcp_user.h>
#endif

/* From net/core/sock.c */
int sysctl_serval_wmem_max __read_mostly = 32767;
int sysctl_serval_rmem_max __read_mostly = 32767;
int sysctl_serval_tcp_window_scaling __read_mostly = 1;

int sysctl_serval_tcp_tso_win_divisor __read_mostly = 3;

/* People can turn this on to work with those rare, broken TCPs that
 * interpret the window field as a signed quantity.
 */
int sysctl_serval_tcp_workaround_signed_windows __read_mostly = 0;

/* By default, RFC2861 behavior.  */
int sysctl_serval_tcp_slow_start_after_idle __read_mostly = 1;

#define OPTION_SACK_ADVERTISE	(1 << 0)
#define OPTION_TS		(1 << 1)
#define OPTION_MD5		(1 << 2)
#define OPTION_WSCALE		(1 << 3)
#define OPTION_COOKIE_EXTENSION	(1 << 4)

struct tcp_out_options {
	u8 options;		/* bit field of OPTION_* */
	u8 ws;			/* window scale, 0 to disable */
	u8 num_sack_blocks;	/* number of SACK blocks to include */
	u8 hash_size;		/* bytes in hash_location */
	u16 mss;		/* 0 to disable */
	__u32 tsval, tsecr;	/* need to include OPTION_TS */
	__u8 *hash_location;	/* temporary pointer, overloaded */
};


/* SND.NXT, if window was not shrunk.
 * If window has been shrunk, what should we make? It is not clear at all.
 * Using SND.UNA we will fail to open window, SND.NXT is out of window. :-(
 * Anything in between SND.UNA...SND.UNA+SND.WND also can be already
 * invalid. OK, let's make this for now:
 */
static inline __u32 serval_tcp_acceptable_seq(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (!before(serval_tcp_wnd_end(tp), tp->snd_nxt))
		return tp->snd_nxt;
	else
		return serval_tcp_wnd_end(tp);
}


static inline int serval_tcp_urg_mode(const struct serval_tcp_sock *tp)
{
	return tp->snd_una != tp->snd_up;
}

/* Compute TCP options for SYN packets. This is not the final
 * network wire format yet.
 */
static unsigned serval_tcp_syn_options(struct sock *sk, struct sk_buff *skb,
				       struct tcp_out_options *opts,
				       struct tcp_md5sig_key **md5) 
{
	/* Not implemented */
	return 0;
}

/* Set up TCP options for SYN-ACKs. */
static unsigned serval_tcp_synack_options(struct sock *sk,
					  struct serval_request_sock *req,
					  unsigned mss, struct sk_buff *skb,
					  struct tcp_out_options *opts,
					  struct tcp_md5sig_key **md5,
					  struct tcp_extend_values *xvp)
{
	/* Not implemented */
	return 0;
}

/* Compute TCP options for ESTABLISHED sockets. This is not the
 * final wire format yet.
 */
static unsigned serval_tcp_established_options(struct sock *sk, 
					       struct sk_buff *skb,
					       struct tcp_out_options *opts,
					       struct tcp_md5sig_key **md5) 
{
	return 0;
}

/* Account for new data that has been sent to the network. */
static void serval_tcp_event_new_data_sent(struct sock *sk, struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	//unsigned int prior_packets = tp->packets_out;

	serval_tcp_advance_send_head(sk, skb);
	tp->snd_nxt = TCP_SKB_CB(skb)->end_seq;

	/* Don't override Nagle indefinately with F-RTO */
	if (tp->frto_counter == 2)
		tp->frto_counter = 3;

	tp->packets_out += tcp_skb_pcount(skb);
	/*
	if (!prior_packets)
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
					  inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
	*/
}

/* RFC2861. Reset CWND after idle period longer RTO to "restart window".
 * This is the first part of cwnd validation mechanism. */
static void serval_tcp_cwnd_restart(struct sock *sk, struct dst_entry *dst)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	s32 delta = tcp_time_stamp - tp->lsndtime;
	u32 restart_cwnd = serval_tcp_init_cwnd(tp, dst);
	u32 cwnd = tp->snd_cwnd;

	serval_tcp_ca_event(sk, CA_EVENT_CWND_RESTART);

	tp->snd_ssthresh = serval_tcp_current_ssthresh(sk);
	restart_cwnd = min(restart_cwnd, cwnd);

	while ((delta -= tp->rto) > 0 && cwnd > restart_cwnd)
		cwnd >>= 1;
	tp->snd_cwnd = max(cwnd, restart_cwnd);
	tp->snd_cwnd_stamp = tcp_time_stamp;
	tp->snd_cwnd_used = 0;
}

/* Congestion state accounting after a packet has been sent. */
static void serval_tcp_event_data_sent(struct serval_tcp_sock *tp,
				       struct sk_buff *skb, struct sock *sk)
{
	const u32 now = tcp_time_stamp;

	if (sysctl_serval_tcp_slow_start_after_idle &&
	    (!tp->packets_out && (s32)(now - tp->lsndtime) > tp->rto))
		serval_tcp_cwnd_restart(sk, __sk_dst_get(sk));

	tp->lsndtime = now;

	/* If it is a reply for ato after last received
	 * packet, enter pingpong mode.
	 */
	if ((u32)(now - tp->tp_ack.lrcvtime) < tp->tp_ack.ato)
		tp->tp_ack.pingpong = 1;
}

/* Account for an ACK we sent. */
static inline void serval_tcp_event_ack_sent(struct sock *sk, unsigned int pkts)
{
	//tcp_dec_quickack_mode(sk, pkts);
	//inet_csk_clear_xmit_timer(sk, ICSK_TIME_DACK);
}

/* Initialize TSO segments for a packet. */
static void serval_tcp_set_skb_tso_segs(struct sock *sk, struct sk_buff *skb,
					unsigned int mss_now)
{
	if (skb->len <= mss_now || !sk_can_gso(sk) ||
	    skb->ip_summed == CHECKSUM_NONE) {
		/* Avoid the costly divide in the normal
		 * non-TSO case.
		 */
		skb_shinfo(skb)->gso_segs = 1;
		skb_shinfo(skb)->gso_size = 0;
		skb_shinfo(skb)->gso_type = 0;
	} else {
		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len, mss_now);
		skb_shinfo(skb)->gso_size = mss_now;
		skb_shinfo(skb)->gso_type = sk->sk_gso_type;
	}
}

/* Intialize TSO state of a skb.
 * This must be invoked the first time we consider transmitting
 * SKB onto the wire.
 */
static int serval_tcp_init_tso_segs(struct sock *sk, struct sk_buff *skb,
				    unsigned int mss_now)
{
	int tso_segs = tcp_skb_pcount(skb);

	if (!tso_segs || (tso_segs > 1 && tcp_skb_mss(skb) != mss_now)) {
		serval_tcp_set_skb_tso_segs(sk, skb, mss_now);
		tso_segs = tcp_skb_pcount(skb);
	}
	return tso_segs;
}


/* Determine a window scaling and initial window to offer.
 * Based on the assumption that the given amount of space
 * will be offered. Store the results in the tp structure.
 * NOTE: for smooth operation initial space offering should
 * be a multiple of mss if possible. We assume here that mss >= 1.
 * This MUST be enforced by all callers.
 */
void serval_tcp_select_initial_window(int __space, __u32 mss,
                                      __u32 *rcv_wnd, __u32 *window_clamp,
                                      int wscale_ok, __u8 *rcv_wscale,
                                      __u32 init_rcv_wnd)
{
	unsigned int space = (__space < 0 ? 0 : __space);

        LOG_DBG("1. space=%u mss=%u rcv_wnd=%u window_clamp=%u init_rcv_wnd=%u\n", space, mss, *rcv_wnd, *window_clamp, init_rcv_wnd);
	/* If no clamp set the clamp to the max possible scaled window */
	if (*window_clamp == 0)
		(*window_clamp) = (65535 << 14);
	space = min(*window_clamp, space);

	/* Quantize space offering to a multiple of mss if possible. */
	if (space > mss)
		space = (space / mss) * mss;

	/* NOTE: offering an initial window larger than 32767
	 * will break some buggy TCP stacks. If the admin tells us
	 * it is likely we could be speaking with such a buggy stack
	 * we will truncate our initial window offering to 32K-1
	 * unless the remote has sent us a window scaling option,
	 * which we interpret as a sign the remote TCP is not
	 * misinterpreting the window field as a signed quantity.
	 */
	if (sysctl_serval_tcp_workaround_signed_windows)
		(*rcv_wnd) = min(space, MAX_TCP_WINDOW);
	else
		(*rcv_wnd) = space;

	(*rcv_wscale) = 0;
	if (wscale_ok) {
		/* Set window scaling on max possible window
		 * See RFC1323 for an explanation of the limit to 14
		 */
		space = max_t(u32, sysctl_tcp_rmem[2], sysctl_serval_rmem_max);
		space = min_t(u32, space, *window_clamp);
		while (space > 65535 && (*rcv_wscale) < 14) {
			space >>= 1;
			(*rcv_wscale)++;
		}
	}

	/* Set initial window to value enough for senders,
	 * following RFC2414. Senders, not following this RFC,
	 * will be satisfied with 2.
	 */
	if (mss > (1 << *rcv_wscale)) {
		int init_cwnd = 4;
		if (mss > 1460 * 3)
			init_cwnd = 2;
		else if (mss > 1460)
			init_cwnd = 3;
		/* when initializing use the value from init_rcv_wnd
		 * rather than the default from above
		 */
		if (init_rcv_wnd &&
		    (*rcv_wnd > init_rcv_wnd * mss))
			*rcv_wnd = init_rcv_wnd * mss;
		else if (*rcv_wnd > init_cwnd * mss)
			*rcv_wnd = init_cwnd * mss;
	}

	/* Set the clamp no higher than max representable value */
	(*window_clamp) = min(65535U << (*rcv_wscale), *window_clamp);
        
        LOG_DBG("2. space=%u mss=%u rcv_wnd=%u window_clamp=%u init_rcv_wnd=%u\n", space, mss, *rcv_wnd, *window_clamp, init_rcv_wnd);
}


/* Chose a new window to advertise, update state in tcp_sock for the
 * socket, and return result with RFC1323 scaling applied.  The return
 * value can be stuffed directly into th->window for an outgoing
 * frame.
 */
static u16 serval_tcp_select_window(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	u32 cur_win = serval_tcp_receive_window(tp);
	u32 new_win = __serval_tcp_select_window(sk);

	/* Never shrink the offered window */
	if (new_win < cur_win) {
		/* Danger Will Robinson!
		 * Don't update rcv_wup/rcv_wnd here or else
		 * we will not be able to advertise a zero
		 * window in time.  --DaveM
		 *
		 * Relax Will Robinson.
		 */
		new_win = ALIGN(cur_win, 1 << tp->rx_opt.rcv_wscale);
	}
	tp->rcv_wnd = new_win;
	tp->rcv_wup = tp->rcv_nxt;

	/* Make sure we do not exceed the maximum possible
	 * scaled window.
	 */
	if (!tp->rx_opt.rcv_wscale && sysctl_serval_tcp_workaround_signed_windows)
		new_win = min(new_win, MAX_TCP_WINDOW);
	else
		new_win = min(new_win, (65535U << tp->rx_opt.rcv_wscale));

	/* RFC1323 scaling applied */
	new_win >>= tp->rx_opt.rcv_wscale;

	/* If we advertise zero window, disable fast path. */
	if (new_win == 0)
		tp->pred_flags = 0;

	return new_win;
}


/* Congestion window validation. (RFC2861) */
static void serval_tcp_cwnd_validate(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (tp->packets_out >= tp->snd_cwnd) {
		/* Network is feed fully. */
		tp->snd_cwnd_used = 0;
		tp->snd_cwnd_stamp = tcp_time_stamp;
	} else {
		/* Network starves. */
		if (tp->packets_out > tp->snd_cwnd_used)
			tp->snd_cwnd_used = tp->packets_out;

		if (sysctl_serval_tcp_slow_start_after_idle &&
		    (s32)(tcp_time_stamp - tp->snd_cwnd_stamp) >= tp->rto)
			serval_tcp_cwnd_application_limited(sk);
	}
}


/* Returns the portion of skb which can be sent right away without
 * introducing MSS oddities to segment boundaries. In rare cases where
 * mss_now != mss_cache, we will request caller to create a small skb
 * per input skb which could be mostly avoided here (if desired).
 *
 * We explicitly want to create a request for splitting write queue tail
 * to a small skb for Nagle purposes while avoiding unnecessary modulos,
 * thus all the complexity (cwnd_len is always MSS multiple which we
 * return whenever allowed by the other factors). Basically we need the
 * modulo only when the receiver window alone is the limiting factor or
 * when we would be allowed to send the split-due-to-Nagle skb fully.
 */
static unsigned int serval_tcp_mss_split_point(struct sock *sk, 
					       struct sk_buff *skb,
					       unsigned int mss_now, 
					       unsigned int cwnd)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	u32 needed, window, cwnd_len;

	window = serval_tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;
	cwnd_len = mss_now * cwnd;

	if (likely(cwnd_len <= window && 
		   skb != serval_tcp_write_queue_tail(sk)))
		return cwnd_len;

	needed = min(skb->len, window);

	if (cwnd_len <= needed)
		return cwnd_len;

	return needed - needed % mss_now;
}


/* Can at least one segment of SKB be sent right now, according to the
 * congestion window rules?  If so, return how many segments are allowed.
 */
static inline unsigned int serval_tcp_cwnd_test(struct serval_tcp_sock *tp,
						struct sk_buff *skb)
{
	u32 in_flight, cwnd;

	/* Don't be strict about the congestion window for the final FIN.  */
	if ((TCP_SKB_CB(skb)->flags & TCPH_FIN) &&
	    tcp_skb_pcount(skb) == 1)
		return 1;

	in_flight = serval_tcp_packets_in_flight(tp);
	cwnd = tp->snd_cwnd;
	if (in_flight < cwnd)
		return (cwnd - in_flight);

	return 0;
}

/* Does at least the first segment of SKB fit into the send window? */
static inline int serval_tcp_snd_wnd_test(struct serval_tcp_sock *tp, 
					  struct sk_buff *skb,
					  unsigned int cur_mss)
{
	u32 end_seq = TCP_SKB_CB(skb)->end_seq;
        int ret;

        LOG_DBG("skb->len=%u cur_mss=%u end_seq=%u wnd_end=%u\n", 
                skb->len, cur_mss, end_seq, serval_tcp_wnd_end(tp));

	if (skb->len > cur_mss)
		end_seq = TCP_SKB_CB(skb)->seq + cur_mss;

	ret = !after(end_seq, serval_tcp_wnd_end(tp));

        LOG_DBG("ret=%d\n", ret);

        return ret;
}

/* This checks if the data bearing packet SKB (usually tcp_send_head(sk))
 * should be put on the wire right now.  If so, it returns the number of
 * packets allowed by the congestion window.
 */
static unsigned int serval_tcp_snd_test(struct sock *sk, struct sk_buff *skb,
					unsigned int cur_mss, int nonagle)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	unsigned int cwnd_quota;

	serval_tcp_init_tso_segs(sk, skb, cur_mss);

	/*
	if (!tcp_nagle_test(tp, skb, cur_mss, nonagle))
		return 0;
	*/

	cwnd_quota = serval_tcp_cwnd_test(tp, skb);
	if (cwnd_quota && !serval_tcp_snd_wnd_test(tp, skb, cur_mss))
		cwnd_quota = 0;

	return cwnd_quota;
}

/* This routine just queues the buffer for sending.
 *
 * NOTE: probe0 timer is not checked, do not forget tcp_push_pending_frames,
 * otherwise socket can stall.
 */
static void serval_tcp_queue_skb(struct sock *sk, struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	/* Advance write_seq and place onto the write_queue. */
	tp->write_seq = TCP_SKB_CB(skb)->end_seq;
	skb_header_release(skb);
	serval_tcp_add_write_queue_tail(sk, skb);
	sk->sk_wmem_queued += skb->truesize;
	sk_mem_charge(sk, skb->truesize);
}



/* This routine actually transmits TCP packets queued in by
 * tcp_do_sendmsg().  This is used by both the initial
 * transmission and possible later retransmissions.
 * All SKB's seen here are completely headerless.  It is our
 * job to build the TCP header, and pass the packet down to
 * IP so it can do the same plus pass the packet off to the
 * device.
 *
 * We are working here with either a clone of the original
 * SKB, or a fresh unique copy made by the retransmit engine.
 */
static int serval_tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, 
				   int clone_it, gfp_t gfp_mask)
{
	struct serval_sock *ssk = serval_sk(sk);
	struct inet_sock *inet;
	struct serval_tcp_sock *tp;
	struct tcp_skb_cb *tcb;
	struct tcp_out_options opts;
	unsigned tcp_options_size, tcp_header_size;
	struct tcp_md5sig_key *md5;
	struct tcphdr *th;
	int err;

        LOG_DBG("Transmitting TCP packet len=%u\n", skb->len);

	BUG_ON(!skb || !tcp_skb_pcount(skb));

	/* If congestion control is doing timestamping, we must
	 * take such a timestamp before we potentially clone/copy.
	 */
	/*
	if (icsk->icsk_ca_ops->flags & TCP_CONG_RTT_STAMP)
		__net_timestamp(skb);
	*/
	if (likely(clone_it)) {
		if (unlikely(skb_cloned(skb)))
			skb = pskb_copy(skb, gfp_mask);
		else
			skb = skb_clone(skb, gfp_mask);
		if (unlikely(!skb))
			return -ENOBUFS;
	}

	inet = inet_sk(sk);
	tp = serval_tcp_sk(sk);
	tcb = TCP_SKB_CB(skb);
	memset(&opts, 0, sizeof(opts));

	if (unlikely(tcb->flags & TCPH_SYN))
		tcp_options_size = serval_tcp_syn_options(sk, skb, &opts, &md5);
	else
		tcp_options_size = serval_tcp_established_options(sk, skb, 
								  &opts,
								  &md5);

	tcp_header_size = tcp_options_size + sizeof(struct tcphdr);

	if (serval_tcp_packets_in_flight(tp) == 0)
		serval_tcp_ca_event(sk, CA_EVENT_TX_START);

	skb_push(skb, tcp_header_size);
	skb_reset_transport_header(skb);
	skb_set_owner_w(skb, sk);

	/* Build TCP header and checksum it. */
	th = tcp_hdr(skb);
	th->source		= 0;
	th->dest		= 0;
	th->seq			= htonl(tcb->seq);
	th->ack_seq		= htonl(tp->rcv_nxt);
	*(((__be16 *)th) + 6)	= htons(((tcp_header_size >> 2) << 12) |
					tcb->flags);

	if (unlikely(tcb->flags & TCPH_SYN)) {
		/* RFC1323: The window in SYN & SYN/ACK segments
		 * is never scaled.
		 */
		th->window	= htons(min(tp->rcv_wnd, 65535U));
	} else {
		th->window	= htons(serval_tcp_select_window(sk));
	}
	th->check		= 0;
	th->urg_ptr		= 0;

	/* The urg_mode check is necessary during a below snd_una win probe */
	if (unlikely(serval_tcp_urg_mode(tp) && before(tcb->seq, tp->snd_up))) {
		if (before(tp->snd_up, tcb->seq + 0x10000)) {
			th->urg_ptr = htons(tp->snd_up - tcb->seq);
			th->urg = 1;
		} else if (after(tcb->seq + 0xFFFF, tp->snd_nxt)) {
			th->urg_ptr = htons(0xFFFF);
			th->urg = 1;
		}
	}

	//tcp_options_write((__be32 *)(th + 1), tp, &opts);
	
	/*
	if (likely((tcb->flags & TCPH_SYN) == 0))
		TCP_ECN_send(sk, skb, tcp_header_size);
	*/
#ifdef CONFIG_TCP_MD5SIG_DISABLED
	/* Calculate the MD5 hash, as we have all we need now */
	if (md5) {
		sk_nocaps_add(sk, NETIF_F_GSO_MASK);
		tp->af_specific->calc_md5_hash(opts.hash_location,
					       md5, sk, NULL, skb);
	}
#endif

        if (ssk->af_ops->send_check)
                ssk->af_ops->send_check(sk, skb);

	if (likely(tcb->flags & TCPH_ACK))
		serval_tcp_event_ack_sent(sk, tcp_skb_pcount(skb));

	if (skb->len != tcp_header_size)
		serval_tcp_event_data_sent(tp, skb, sk);

	if (after(tcb->end_seq, tp->snd_nxt) || tcb->seq == tcb->end_seq) {
		/*
		TCP_ADD_STATS(sock_net(sk), TCP_MIB_OUTSEGS,
			      tcp_skb_pcount(skb));
		*/
	}

        LOG_DBG("queue_xmit\n");

	err = serval_srv_xmit_skb(skb);
        //ssk->af_ops->queue_xmit(skb);

	if (likely(err <= 0))
		return err;

	serval_tcp_enter_cwr(sk, 1);

	return net_xmit_eval(err);
}


/* Create a new MTU probe if we are ready.
 * MTU probe is regularly attempting to increase the path MTU by
 * deliberately sending larger packets.  This discovers routing
 * changes resulting in larger path MTUs.
 *
 * Returns 0 if we should wait to probe (no cwnd available),
 *         1 if a probe was sent,
 *         -1 otherwise
 */
static int serval_tcp_mtu_probe(struct sock *sk)
{
        LOG_WARN("MTU probing not implemented!\n");
	return 1;
}

static int serval_tcp_write_xmit(struct sock *sk, unsigned int mss_now, 
				 int nonagle, int push_one, gfp_t gfp)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *skb;
	unsigned int tso_segs, sent_pkts;
	int cwnd_quota;
	int result;

	sent_pkts = 0;

	if (!push_one) {
		/* Do MTU probing. */
                LOG_DBG("Doing MTU probing\n");

		result = serval_tcp_mtu_probe(sk);

		if (!result) {
                        LOG_DBG("MTU probing result=%d\n", result);
			return 0;
		} else if (result > 0) {
			sent_pkts = 1;
		}
	}

        LOG_DBG("Checking send queue\n");

	while ((skb = serval_tcp_send_head(sk))) {
		unsigned int limit;

		tso_segs = serval_tcp_init_tso_segs(sk, skb, mss_now);
		BUG_ON(!tso_segs);

		cwnd_quota = serval_tcp_cwnd_test(tp, skb);

		if (!cwnd_quota) {
                        LOG_DBG("cwnd_quota=%d\n", cwnd_quota);
                        break;
                }

		if (unlikely(!serval_tcp_snd_wnd_test(tp, skb, mss_now))) {
                        LOG_DBG("tcp_snd_wnd_test failed!\n");
			break;
                }

		/*
		if (tso_segs == 1) {
			if (unlikely(!tcp_nagle_test(tp, skb, mss_now,
						     (tcp_skb_is_last(sk, skb) ?
						      nonagle : TCP_NAGLE_PUSH))))
				break;
		} else {
			if (!push_one && tcp_tso_should_defer(sk, skb))
				break;
		}
		*/

		limit = mss_now;
		if (tso_segs > 1 && !serval_tcp_urg_mode(tp))
			limit = serval_tcp_mss_split_point(sk, skb, mss_now,
							   cwnd_quota);

		/*
		if (skb->len > limit &&
		    unlikely(serval_tso_fragment(sk, skb, limit, mss_now)))
			break;
		*/
		TCP_SKB_CB(skb)->when = tcp_time_stamp;

                LOG_DBG("tcp_transmit_skb\n");

		if (unlikely(serval_tcp_transmit_skb(sk, skb, 1, gfp)))
			break;

		/* Advance the send_head.  This one is sent out.
		 * This call will increment packets_out.
		 */
		serval_tcp_event_new_data_sent(sk, skb);

		serval_tcp_minshall_update(tp, mss_now, skb);
		sent_pkts++;

		if (push_one)
			break;
	}

	if (likely(sent_pkts)) {
		serval_tcp_cwnd_validate(sk);
		return 0;
	}

	return !tp->packets_out && serval_tcp_send_head(sk);
}

/* Push out any pending frames which were held back due to
 * TCP_CORK or attempt at coalescing tiny packets.
 * The socket must be locked by the caller.
 */
void __serval_tcp_push_pending_frames(struct sock *sk, unsigned int cur_mss,
                                      int nonagle)
{
	/* If we are closed, the bytes will have to remain here.
	 * In time closedown will finish, we empty the write queue and
	 * all will be happy.
	 */
	if (unlikely(sk->sk_state == TCP_CLOSE))
		return;

        LOG_DBG("tcp_write_xmit\n");

	if (serval_tcp_write_xmit(sk, cur_mss, nonagle, 0, GFP_ATOMIC))
		serval_tcp_check_probe_timer(sk);
}


/* Send _single_ skb sitting at the send head. This function requires
 * true push pending frames to setup probe timer etc.
 */
void serval_tcp_push_one(struct sock *sk, unsigned int mss_now)
{
	struct sk_buff *skb = serval_tcp_send_head(sk);

	BUG_ON(!skb || skb->len < mss_now);

	serval_tcp_write_xmit(sk, mss_now, 
			      TCP_NAGLE_PUSH, 1, sk->sk_allocation);
}


/* This function returns the amount that we can raise the
 * usable window based on the following constraints
 *
 * 1. The window can never be shrunk once it is offered (RFC 793)
 * 2. We limit memory per socket
 *
 * RFC 1122:
 * "the suggested [SWS] avoidance algorithm for the receiver is to keep
 *  RECV.NEXT + RCV.WIN fixed until:
 *  RCV.BUFF - RCV.USER - RCV.WINDOW >= min(1/2 RCV.BUFF, MSS)"
 *
 * i.e. don't raise the right edge of the window until you can raise
 * it at least MSS bytes.
 *
 * Unfortunately, the recommended algorithm breaks header prediction,
 * since header prediction assumes th->window stays fixed.
 *
 * Strictly speaking, keeping th->window fixed violates the receiver
 * side SWS prevention criteria. The problem is that under this rule
 * a stream of single byte packets will cause the right side of the
 * window to always advance by a single byte.
 *
 * Of course, if the sender implements sender side SWS prevention
 * then this will not be a problem.
 *
 * BSD seems to make the following compromise:
 *
 *	If the free space is less than the 1/4 of the maximum
 *	space available and the free space is less than 1/2 mss,
 *	then set the window to 0.
 *	[ Actually, bsd uses MSS and 1/4 of maximal _window_ ]
 *	Otherwise, just prevent the window from shrinking
 *	and from being larger than the largest representable value.
 *
 * This prevents incremental opening of the window in the regime
 * where TCP is limited by the speed of the reader side taking
 * data out of the TCP receive queue. It does nothing about
 * those cases where the window is constrained on the sender side
 * because the pipeline is full.
 *
 * BSD also seems to "accidentally" limit itself to windows that are a
 * multiple of MSS, at least until the free space gets quite small.
 * This would appear to be a side effect of the mbuf implementation.
 * Combining these two algorithms results in the observed behavior
 * of having a fixed window size at almost all times.
 *
 * Below we obtain similar behavior by forcing the offered window to
 * a multiple of the mss when it is feasible to do so.
 *
 * Note, we don't "adjust" for TIMESTAMP or SACK option bytes.
 * Regular options like TIMESTAMP are taken into account.
 */
u32 __serval_tcp_select_window(struct sock *sk)
{
	//struct inet_connection_sock *icsk = inet_csk(sk);
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	/* MSS for the peer's data.  Previous versions used mss_clamp
	 * here.  I don't know if the value based on our guesses
	 * of peer's MSS is better for the performance.  It's more correct
	 * but may be worse for the performance because of rcv_mss
	 * fluctuations.  --SAW  1998/11/1
	 */
	int mss = tp->tp_ack.rcv_mss;
	int free_space = serval_tcp_space(sk);
	int full_space = min_t(int, tp->window_clamp,
			       serval_tcp_full_space(sk));
	int window;

        LOG_DBG("tp->tp_ack.rcv_mss=%u window_clamp=%d "
                "free_space=%d tcp_full_space=%d\n", 
                tp->tp_ack.rcv_mss, 
                tp->window_clamp,
                free_space,
                serval_tcp_full_space(sk));

	if (mss > full_space)
		mss = full_space;

	if (free_space < (full_space >> 1)) {
		tp->tp_ack.quick = 0;

		if (tcp_memory_pressure)
			tp->rcv_ssthresh = min(tp->rcv_ssthresh,
					       4U * tp->advmss);

		if (free_space < mss)
			return 0;
	}

	if (free_space > tp->rcv_ssthresh)
		free_space = tp->rcv_ssthresh;

        LOG_DBG("free_space=%d\n", free_space);

	/* Don't do rounding if we are using window scaling, since the
	 * scaled window will not line up with the MSS boundary anyway.
	 */
	window = tp->rcv_wnd;
	if (tp->rx_opt.rcv_wscale) {
		window = free_space;

		/* Advertise enough space so that it won't get scaled away.
		 * Import case: prevent zero window announcement if
		 * 1<<rcv_wscale > mss.
		 */
		if (((window >> tp->rx_opt.rcv_wscale) << 
                     tp->rx_opt.rcv_wscale) != window)
			window = (((window >> tp->rx_opt.rcv_wscale) + 1)
				  << tp->rx_opt.rcv_wscale);
	} else {
		/* Get the largest window that is a nice multiple of mss.
		 * Window clamp already applied above.
		 * If our current window offering is within 1 mss of the
		 * free space we just keep it. This prevents the divide
		 * and multiply from happening most of the time.
		 * We also don't do any window rounding when the free space
		 * is too small.
		 */

                LOG_DBG("window=%u free_space=%u mss=%u\n",
                        window, free_space, mss);

		if (window <= free_space - mss || window > free_space)
			window = (free_space / mss) * mss;
		else if (mss == full_space &&
			 free_space > window + (full_space >> 1))
			window = free_space;
	}

	return window;
}

/* This is similar to __pskb_pull_head() (it will go to core/skbuff.c
 * eventually). The difference is that pulled data not copied, but
 * immediately discarded.
 */
static void __pskb_trim_head(struct sk_buff *skb, int len)
{
#if defined(OS_LINUX_KERNEL)
	int i, k, eat;

	eat = len;
	k = 0;
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		if (skb_shinfo(skb)->frags[i].size <= eat) {
			put_page(skb_shinfo(skb)->frags[i].page);
			eat -= skb_shinfo(skb)->frags[i].size;
		} else {
			skb_shinfo(skb)->frags[k] = skb_shinfo(skb)->frags[i];
			if (eat) {
				skb_shinfo(skb)->frags[k].page_offset += eat;
				skb_shinfo(skb)->frags[k].size -= eat;
				eat = 0;
			}
			k++;
		}
	}
	skb_shinfo(skb)->nr_frags = k;
#endif
	skb_reset_tail_pointer(skb);
	skb->data_len -= len;
	skb->len = skb->data_len;
}

/* Remove acked data from a packet in the transmit queue. */
int serval_tcp_trim_head(struct sock *sk, struct sk_buff *skb, u32 len)
{
	if (skb_cloned(skb) && pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
		return -ENOMEM;

	/* If len == headlen, we avoid __skb_pull to preserve alignment. */
	if (unlikely(len < skb_headlen(skb)))
		__skb_pull(skb, len);
	else
		__pskb_trim_head(skb, len - skb_headlen(skb));

	TCP_SKB_CB(skb)->seq += len;
	skb->ip_summed = CHECKSUM_PARTIAL;

	skb->truesize	     -= len;
	sk->sk_wmem_queued   -= len;
	sk_mem_uncharge(sk, len);
	sock_set_flag(sk, SOCK_QUEUE_SHRUNK);

	/* Any change of skb->len requires recalculation of tso
	 * factor and mss.
	 */
	if (serval_tcp_skb_pcount(skb) > 1)
		serval_tcp_set_skb_tso_segs(sk, skb, 
                                            serval_tcp_current_mss(sk));

	return 0;
}

/* Calculate MSS. Not accounting for SACKs here.  */
int serval_tcp_mtu_to_mss(struct sock *sk, int pmtu)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int mss_now;

	/* Calculate base mss without TCP options:
	   It is MMS_S - sizeof(tcphdr) of rfc1122
	 */
	///mss_now = pmtu - icsk->icsk_af_ops->net_header_len - sizeof(struct tcphdr);
	mss_now = pmtu - MAX_SERVAL_HDR - sizeof(struct tcphdr);

	/* Clamp it (mss_clamp does not include tcp options) */
	if (mss_now > tp->rx_opt.mss_clamp)
		mss_now = tp->rx_opt.mss_clamp;

	/* Now subtract optional transport overhead */
	//mss_now -= icsk->icsk_ext_hdr_len;

	/* Then reserve room for full set of TCP options and 8 bytes of data */
	if (mss_now < 48)
		mss_now = 48;

	/* Now subtract TCP options size, not including SACKs */
	mss_now -= tp->tcp_header_len - sizeof(struct tcphdr);

	return mss_now;
}

/* Inverse of above */
int serval_tcp_mss_to_mtu(struct sock *sk, int mss)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	//struct inet_connection_sock *icsk = inet_csk(sk);
	int mtu;
        /*
	mtu = mss +
	      tp->tcp_header_len +
	      icsk->icsk_ext_hdr_len +
	      icsk->icsk_af_ops->net_header_len;
        */

	mtu = mss +
	      tp->tcp_header_len +
                MAX_SERVAL_HDR;

        
	return mtu;
}


/* MTU probing init per socket */
void serval_tcp_mtup_init(struct sock *sk)
{
        LOG_WARN("MTU probing not implemented\n");
}


/* This function synchronize snd mss to current pmtu/exthdr set.

   tp->rx_opt.user_mss is mss set by user by TCP_MAXSEG. It does NOT counts
   for TCP options, but includes only bare TCP header.

   tp->rx_opt.mss_clamp is mss negotiated at connection setup.
   It is minimum of user_mss and mss received with SYN.
   It also does not include TCP options.

   inet_csk(sk)->icsk_pmtu_cookie is last pmtu, seen by this function.

   tp->mss_cache is current effective sending mss, including
   all tcp options except for SACKs. It is evaluated,
   taking into account current pmtu, but never exceeds
   tp->rx_opt.mss_clamp.

   NOTE1. rfc1122 clearly states that advertised MSS
   DOES NOT include either tcp or ip options.

   NOTE2. inet_csk(sk)->icsk_pmtu_cookie and tp->mss_cache
   are READ ONLY outside this function.		--ANK (980731)
 */
unsigned int serval_tcp_sync_mss(struct sock *sk, u32 pmtu)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int mss_now;

        /*
	if (icsk->icsk_mtup.search_high > pmtu)
		icsk->icsk_mtup.search_high = pmtu;
        */
	mss_now = serval_tcp_mtu_to_mss(sk, pmtu);
	mss_now = serval_tcp_bound_to_half_wnd(tp, mss_now);

	/* And store cached results */
        /*
	icsk->icsk_pmtu_cookie = pmtu;
	if (icsk->icsk_mtup.enabled)
		mss_now = min(mss_now, tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_low));
        */
	tp->mss_cache = mss_now;

	return mss_now;
}

/* Compute the current effective MSS, taking SACKs and IP options,
 * and even PMTU discovery events into account.
 */
unsigned int serval_tcp_current_mss(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct dst_entry *dst = __sk_dst_get(sk);
	u32 mss_now;
	unsigned header_len;
	struct tcp_out_options opts;
	struct tcp_md5sig_key *md5;

	mss_now = tp->mss_cache;

	if (dst) {
		u32 mtu = dst_mtu(dst);
                /*
		if (mtu != inet_csk(sk)->icsk_pmtu_cookie)
			mss_now = tcp_sync_mss(sk, mtu);
                */

                mss_now = serval_tcp_sync_mss(sk, mtu);
	}

	header_len = serval_tcp_established_options(sk, NULL, &opts, &md5) +
                sizeof(struct tcphdr);
	/* The mss_cache is sized based on tp->tcp_header_len, which assumes
	 * some common options. If this is an odd packet (because we have SACK
	 * blocks etc) then our calculated header_len will be different, and
	 * we have to adjust mss_now correspondingly */
	if (header_len != tp->tcp_header_len) {
		int delta = (int) header_len - tp->tcp_header_len;
		mss_now -= delta;
	}

	return mss_now;
}

/**
   FIXME: Lots of hard coded stuff in this init function as the user
   space version of the stack does not have dst cache
   implemented. Therefore we cannot access the default dst_metrics.

 */
static void serval_tcp_connect_init(struct sock *sk)
{
	//struct dst_entry *dst = __sk_dst_get(sk);
        struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	__u8 rcv_wscale;
        //unsigned int initrwnd = dst_metric(dst, RTAX_INITRWND);
        unsigned int initrwnd = 65535;

        tp->tcp_header_len = sizeof(struct tcphdr);
 
	if (tp->rx_opt.user_mss)
		tp->rx_opt.mss_clamp = tp->rx_opt.user_mss;
	tp->max_window = 0;
	serval_tcp_mtup_init(sk);
	//serval_tcp_sync_mss(sk, dst_mtu(dst));
        serval_tcp_sync_mss(sk, 1500);

	if (!tp->window_clamp) {
		//tp->window_clamp = dst_metric(dst, RTAX_WINDOW);
                tp->window_clamp = 65535;
        }
	//tp->advmss = dst_metric(dst, RTAX_ADVMSS);
        tp->advmss = TCP_MSS_DEFAULT;

	if (tp->rx_opt.user_mss && tp->rx_opt.user_mss < tp->advmss)
		tp->advmss = tp->rx_opt.user_mss;

	serval_tcp_initialize_rcv_mss(sk);

	serval_tcp_select_initial_window(serval_tcp_full_space(sk),
                                         tp->advmss - (tp->rx_opt.ts_recent_stamp ? tp->tcp_header_len - sizeof(struct tcphdr) : 0),
                                         &tp->rcv_wnd,
                                         &tp->window_clamp,
                                         sysctl_serval_tcp_window_scaling,
                                         &rcv_wscale,
                                         initrwnd);

	tp->rx_opt.rcv_wscale = rcv_wscale;
	tp->rcv_ssthresh = tp->rcv_wnd;

	sk->sk_err = 0;
	sock_reset_flag(sk, SOCK_DONE);
	tp->snd_wnd = 0;
	serval_tcp_init_wl(tp, 0);
	tp->snd_una = tp->write_seq;
	tp->snd_sml = tp->write_seq;
	tp->snd_up = tp->write_seq;
	tp->rcv_nxt = 0;
	tp->rcv_wup = 0;
	tp->copied_seq = 0;

        tp->rto = TCP_TIMEOUT_INIT;
	tp->retransmits = 0;
	serval_tcp_clear_retrans(tp);       
}

/* Constructs common control bits of non-data skb. If SYN/FIN is present,
 * auto increment end seqno.
 */
static void serval_tcp_init_nondata_skb(struct sk_buff *skb, u32 seq, u8 flags)
{
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum = 0;
	
        TCP_SKB_CB(skb)->flags = flags;
	TCP_SKB_CB(skb)->sacked = 0;

	skb_shinfo(skb)->gso_segs = 1;
	skb_shinfo(skb)->gso_size = 0;
	skb_shinfo(skb)->gso_type = 0;

	TCP_SKB_CB(skb)->seq = seq;

	if (flags & (TCPH_SYN | TCPH_FIN))
		seq++;

	TCP_SKB_CB(skb)->end_seq = seq;
}


static int serval_tcp_build_header(struct sock *sk, 
                                   struct sk_buff *skb,
                                   u32 seq)
{
        struct tcphdr *th = tcp_hdr(skb);
	struct serval_tcp_sock *tp;
	struct tcp_skb_cb *tcb;
	unsigned tcp_options_size = 0, tcp_header_size;
        
        LOG_DBG("TCP build SYNACK\n");

        tcp_header_size = tcp_options_size + sizeof(struct tcphdr);

	tp = serval_tcp_sk(sk);

	th->seq	       	= htonl(seq);
	th->ack_seq		= htonl(tp->rcv_nxt);
	*(((__be16 *)th) + 6)	= htons(((tcp_header_size >> 2) << 12) |
					tcb->flags);
        if (0 /*unlikely(tcb->flags & TCPH_SYN) */) {
		/* RFC1323: The window in SYN & SYN/ACK segments
		 * is never scaled.
		 */
		th->window	= htons(min(tp->rcv_wnd, 65535U));
	} else {
		th->window	= htons(serval_tcp_select_window(sk));
	}
	th->check		= 0;
	th->urg_ptr		= 0;

        return 0;
}

int serval_tcp_connection_build_syn(struct sock *sk, struct sk_buff *skb)
{
        //struct serval_sock *ssk = serval_sk(sk);
        struct serval_tcp_sock *tp = serval_tcp_sk(sk);
        unsigned int tcp_header_size = sizeof(struct tcphdr);
        struct tcphdr *th;
        u8 flags = TCPH_SYN;

        th = (struct tcphdr *)skb_push(skb, tcp_header_size);

        if (!th) {
                FREE_SKB(skb);
                return -ENOMEM;
        }

        if (!tp->write_seq)
                tp->write_seq = serval_tcp_random_sequence_number();

        serval_tcp_connect_init(sk);

	tp->rx_opt.mss_clamp = TCP_MSS_DEFAULT;

	tp->snd_nxt = tp->write_seq;
	serval_tcp_init_nondata_skb(skb, tp->write_seq, flags);
        th->syn = 1;
	th->source		= htons(1);
	th->dest		= htons(2);
	th->seq		        = htonl(tp->write_seq++);
	th->ack_seq		= htonl(tp->rcv_nxt);
	*(((__be16 *)th) + 6)	= htons(((tcp_header_size >> 2) << 12) |
                                        flags);
                
	tp->packets_out += serval_tcp_skb_pcount(skb);

	tp->snd_nxt = tp->write_seq;
	tp->pushed_seq = tp->write_seq;

        LOG_DBG("TCP sending SYN seq=%u ackno=%u\n",
                ntohl(th->seq), ntohl(th->ack_seq));

        return 0;
}

int serval_tcp_connection_build_synack(struct sock *sk,
                                       struct dst_entry *dst,
                                       struct request_sock *req, 
                                       struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
        struct inet_request_sock *ireq = inet_rsk(req);
	unsigned tcp_header_size;
	struct tcphdr *th;
        int mss;

        th = (struct tcphdr *)skb_push(skb, sizeof(*th));

	mss = TCP_MSS_DEFAULT; //dst_metric(dst, RTAX_ADVMSS);

        LOG_DBG("1. req->window_clamp=%u tp->window_clamp=%u\n",
                req->window_clamp, tp->window_clamp);

	if (req->rcv_wnd == 0) { /* ignored for retransmitted syns */
		__u8 rcv_wscale;
		/* Set this up on the first call only */

		req->window_clamp = tp->window_clamp ? : 
                        TCP_MSS_DEFAULT /*dst_metric(dst, RTAX_WINDOW) */;

		/* tcp_full_space because it is guaranteed to be the
                 * first packet */
		serval_tcp_select_initial_window(serval_tcp_full_space(sk),
                                                 mss
                                                 /* - (tp->tstamp_ok ? TCPOLEN_TSTAMP_ALIGNED : 0) */,
                                                 &req->rcv_wnd,
                                                 &req->window_clamp,
                                                 ireq->wscale_ok,
                                                 &rcv_wscale,
                                                 /* dst_metric(dst, RTAX_INITRWND) */ 1460);
		ireq->rcv_wscale = rcv_wscale;
	}

	serval_tcp_init_nondata_skb(skb, serval_tcp_rsk(req)->snt_isn,
                                     TCPH_SYN | TCPH_ACK);

        tcp_header_size = sizeof(*th);
	memset(th, 0, sizeof(struct tcphdr));
	th->syn = 1;
	th->ack = 1;
	//TCP_ECN_make_synack(req, th);
	th->source = 0;
	th->dest = 0;

        th->seq = htonl(serval_tcp_rsk(req)->snt_isn);
	th->ack_seq = htonl(serval_tcp_rsk(req)->rcv_isn + 1);

	/* RFC1323: The window in SYN & SYN/ACK segments is never scaled. */
	th->window = htons(min(req->rcv_wnd, 65535U));
        th->doff = (tcp_header_size >> 2);

        LOG_DBG("TCP sending SYNACK seq=%u ackno=%u\n",
                ntohl(th->seq), ntohl(th->ack_seq));

        LOG_DBG("2. req->window_clamp=%u tp->window_clamp=%u\n",
                req->window_clamp, tp->window_clamp);

        return 0;
}

int serval_tcp_connection_build_ack(struct sock *sk, 
                                    struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
        unsigned int tcp_header_size = sizeof(struct tcphdr);
        struct tcphdr *th;

        th = (struct tcphdr *)skb_push(skb, tcp_header_size);

        if (!th) {
                FREE_SKB(skb);
                return -ENOMEM;
        }

        memset(th, 0, sizeof(*th));
        th->ack = 1;
	th->source = 0;
	th->dest = 0;
        th->seq = htonl(serval_tcp_acceptable_seq(sk));
	th->ack_seq = htonl(tp->rcv_nxt);
        th->window = htons(serval_tcp_select_window(sk));	
	th->check = 0;
	th->urg_ptr = 0;

        return 0;
}
