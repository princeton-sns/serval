/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/platform.h>
#include <serval/debug.h>
#include <serval/netdevice.h>
#include <serval/skbuff.h>
#include <serval/sock.h>
#include <serval/bitops.h>
#include <serval/dst.h>
#include <netinet/serval.h>
#include <serval_tcp_sock.h>
#include <serval_tcp.h>

int sysctl_serval_tcp_moderate_rcvbuf __read_mostly = 1;
int sysctl_serval_tcp_abc __read_mostly;
int sysctl_serval_tcp_adv_win_scale __read_mostly = 2;
int sysctl_serval_tcp_app_win __read_mostly = 31;

#define FLAG_DATA		0x01 /* Incoming frame contained data.		*/
#define FLAG_WIN_UPDATE		0x02 /* Incoming ACK was a window update.	*/
#define FLAG_DATA_ACKED		0x04 /* This ACK acknowledged new data.		*/
#define FLAG_RETRANS_DATA_ACKED	0x08 /* "" "" some of which was retransmitted.	*/
#define FLAG_SYN_ACKED		0x10 /* This ACK acknowledged SYN.		*/
#define FLAG_DATA_SACKED	0x20 /* New SACK.				*/
#define FLAG_ECE		0x40 /* ECE in this ACK				*/
#define FLAG_DATA_LOST		0x80 /* SACK detected data lossage.		*/
#define FLAG_SLOWPATH		0x100 /* Do not skip RFC checks for window update.*/
#define FLAG_ONLY_ORIG_SACKED	0x200 /* SACKs only non-rexmit sent before RTO */
#define FLAG_SND_UNA_ADVANCED	0x400 /* Snd_una was changed (!= FLAG_DATA_ACKED) */
#define FLAG_DSACKING_ACK	0x800 /* SACK blocks contained D-SACK info */
#define FLAG_NONHEAD_RETRANS_ACKED	0x1000 /* Non-head rexmitted data was ACKed */
#define FLAG_SACK_RENEGING	0x2000 /* snd_una advanced to a sacked seq */

#define FLAG_ACKED		(FLAG_DATA_ACKED|FLAG_SYN_ACKED)
#define FLAG_NOT_DUP		(FLAG_DATA|FLAG_WIN_UPDATE|FLAG_ACKED)
#define FLAG_CA_ALERT		(FLAG_DATA_SACKED|FLAG_ECE)
#define FLAG_FORWARD_PROGRESS	(FLAG_ACKED|FLAG_DATA_SACKED)
#define FLAG_ANY_PROGRESS	(FLAG_FORWARD_PROGRESS|FLAG_SND_UNA_ADVANCED)

#define TCP_REMNANT (TCP_FLAG_FIN|TCP_FLAG_URG|TCP_FLAG_SYN|TCP_FLAG_PSH)
#define TCP_HP_BITS (~(TCP_RESERVED_BITS|TCP_FLAG_PSH))


static void serval_tcp_clear_retrans_partial(struct serval_tcp_sock *tp)
{
	tp->retrans_out = 0;
	tp->lost_out = 0;

	tp->undo_marker = 0;
	tp->undo_retrans = 0;
}

void serval_tcp_clear_retrans(struct serval_tcp_sock *tp)
{
	serval_tcp_clear_retrans_partial(tp);

	tp->fackets_out = 0;
	tp->sacked_out = 0;
}

/* Buffer size and advertised window tuning.
 *
 * 1. Tuning sk->sk_sndbuf, when connection enters established state.
 */

static void serval_tcp_fixup_sndbuf(struct sock *sk)
{
	int sndmem = serval_tcp_sk(sk)->rx_opt.mss_clamp + 
                MAX_SERVAL_TCP_HEADER + 16 + sizeof(struct sk_buff);

	if (sk->sk_sndbuf < 3 * sndmem)
		sk->sk_sndbuf = min(3 * sndmem, sysctl_tcp_wmem[2]);
}


/* 3. Tuning rcvbuf, when connection enters established state. */

static void serval_tcp_fixup_rcvbuf(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int rcvmem = tp->advmss + MAX_SERVAL_TCP_HEADER + 
                16 + sizeof(struct sk_buff);

	/* Try to select rcvbuf so that 4 mss-sized segments
	 * will fit to window and corresponding skbs will fit to our rcvbuf.
	 * (was 3; 4 is minimum to allow fast retransmit to work.)
	 */
	while (serval_tcp_win_from_space(rcvmem) < tp->advmss)
		rcvmem += 128;
	if (sk->sk_rcvbuf < 4 * rcvmem)
		sk->sk_rcvbuf = min(4 * rcvmem, sysctl_tcp_rmem[2]);
}

/* 4. Try to fixup all. It is made immediately after connection enters
 *    established state.
 */
static void serval_tcp_init_buffer_space(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int maxwin;

	if (!(sk->sk_userlocks & SOCK_RCVBUF_LOCK))
		serval_tcp_fixup_rcvbuf(sk);
	if (!(sk->sk_userlocks & SOCK_SNDBUF_LOCK))
		serval_tcp_fixup_sndbuf(sk);
        
	tp->rcvq_space.space = tp->rcv_wnd;

	maxwin = serval_tcp_full_space(sk);

	if (tp->window_clamp >= maxwin) {
		tp->window_clamp = maxwin;

		if (sysctl_serval_tcp_app_win && maxwin > 4 * tp->advmss)
			tp->window_clamp = max(maxwin -
					       (maxwin >> sysctl_serval_tcp_app_win),
					       4 * tp->advmss);
	}

	/* Force reservation of one segment. */
	if (sysctl_serval_tcp_app_win &&
	    tp->window_clamp > 2 * tp->advmss &&
	    tp->window_clamp + tp->advmss > maxwin)
		tp->window_clamp = max(2 * tp->advmss, maxwin - tp->advmss);

	tp->rcv_ssthresh = min(tp->rcv_ssthresh, tp->window_clamp);
	tp->snd_cwnd_stamp = tcp_time_stamp;
}

/* Initialize RCV_MSS value.
 * RCV_MSS is an our guess about MSS used by the peer.
 * We haven't any direct information about the MSS.
 * It's better to underestimate the RCV_MSS rather than overestimate.
 * Overestimations make us ACKing less frequently than needed.
 * Underestimations are more easy to detect and fix by tcp_measure_rcv_mss().
 */
void serval_tcp_initialize_rcv_mss(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	unsigned int hint = min_t(unsigned int, tp->advmss, tp->mss_cache);

	hint = min(hint, tp->rcv_wnd / 2);
	hint = min(hint, TCP_MSS_DEFAULT);
	hint = max(hint, TCP_MIN_MSS);

	tp->tp_ack.rcv_mss = hint;

        LOG_DBG("rcv_mss=%u\n", hint);
}

/*

 * This function should be called every time data is copied to user space.
 * It calculates the appropriate TCP receive buffer space.
 */
void serval_tcp_rcv_space_adjust(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int time;
	int space;

	if (tp->rcvq_space.time == 0)
		goto new_measure;

	time = tcp_time_stamp - tp->rcvq_space.time;
	if (time < (tp->rcv_rtt_est.rtt >> 3) || tp->rcv_rtt_est.rtt == 0)
		return;

	space = 2 * (tp->copied_seq - tp->rcvq_space.seq);

	space = max(tp->rcvq_space.space, space);

	if (tp->rcvq_space.space != space) {
		int rcvmem;

		tp->rcvq_space.space = space;

		if (sysctl_serval_tcp_moderate_rcvbuf &&
		    !(sk->sk_userlocks & SOCK_RCVBUF_LOCK)) {
			int new_clamp = space;

			/* Receive space grows, normalize in order to
			 * take into account packet headers and sk_buff
			 * structure overhead.
			 */
			space /= tp->advmss;
			if (!space)
				space = 1;
			rcvmem = (tp->advmss + MAX_SERVAL_TCP_HEADER +
				  16 + sizeof(struct sk_buff));
			while (serval_tcp_win_from_space(rcvmem) < tp->advmss)
				rcvmem += 128;
			space *= rcvmem;
			space = min(space, sysctl_tcp_rmem[2]);
			if (space > sk->sk_rcvbuf) {
				sk->sk_rcvbuf = space;

				/* Make the window clamp follow along.  */
				tp->window_clamp = new_clamp;
			}
		}
	}

new_measure:
	tp->rcvq_space.seq = tp->copied_seq;
	tp->rcvq_space.time = tcp_time_stamp;
}


/* Numbers are taken from RFC3390.
 *
 * John Heffner states:
 *
 *	The RFC specifies a window of no more than 4380 bytes
 *	unless 2*MSS > 4380.  Reading the pseudocode in the RFC
 *	is a bit misleading because they use a clamp at 4380 bytes
 *	rather than use a multiplier in the relevant range.
 */
__u32 serval_tcp_init_cwnd(struct serval_tcp_sock *tp, struct dst_entry *dst)
{
	__u32 cwnd = (dst ? dst_metric(dst, RTAX_INITCWND) : 0);

	if (!cwnd) {
		if (tp->mss_cache > 1460)
			cwnd = 2;
		else
			cwnd = (tp->mss_cache > 1095) ? 3 : 4;
	}
	return min_t(__u32, cwnd, tp->snd_cwnd_clamp);
}


/* Set slow start threshold and cwnd not falling to slow start */
void serval_tcp_enter_cwr(struct sock *sk, const int set_ssthresh)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	tp->prior_ssthresh = 0;
	tp->bytes_acked = 0;
	if (tp->ca_state < TCP_CA_CWR) {
		tp->undo_marker = 0;
		if (set_ssthresh)
			tp->snd_ssthresh = tp->ca_ops->ssthresh(sk);
		tp->snd_cwnd = min(tp->snd_cwnd,
				   serval_tcp_packets_in_flight(tp) + 1U);
		tp->snd_cwnd_cnt = 0;
		tp->high_seq = tp->snd_nxt;
		tp->snd_cwnd_stamp = tcp_time_stamp;
		//TCP_ECN_queue_cwr(tp);

		serval_tcp_set_ca_state(sk, TCP_CA_CWR);
	}
}

/* RFC2861, slow part. Adjust cwnd, after it was not full during one rto.
 * As additional protections, we do not touch cwnd in retransmission phases,
 * and if application hit its sndbuf limit recently.
 */
void serval_tcp_cwnd_application_limited(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (tp->ca_state == TCP_CA_Open &&
	    sk->sk_socket && !test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		/* Limited by application or receiver window. */
		u32 init_win = serval_tcp_init_cwnd(tp, __sk_dst_get(sk));
		u32 win_used = max(tp->snd_cwnd_used, init_win);
		if (win_used < tp->snd_cwnd) {
			tp->snd_ssthresh = serval_tcp_current_ssthresh(sk);
			tp->snd_cwnd = (tp->snd_cwnd + win_used) >> 1;
		}
		tp->snd_cwnd_used = 0;
	}
	tp->snd_cwnd_stamp = tcp_time_stamp;
}

/* Called to compute a smoothed rtt estimate. The data fed to this
 * routine either comes from timestamps, or from segments that were
 * known _not_ to have been retransmitted [see Karn/Partridge
 * Proceedings SIGCOMM 87]. The algorithm is from the SIGCOMM 88
 * piece by Van Jacobson.
 * NOTE: the next three routines used to be one big routine.
 * To save cycles in the RFC 1323 implementation it was better to break
 * it up into three procedures. -- erics
 */
static void serval_tcp_rtt_estimator(struct sock *sk, const __u32 mrtt)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	long m = mrtt; /* RTT */

	/*	The following amusing code comes from Jacobson's
	 *	article in SIGCOMM '88.  Note that rtt and mdev
	 *	are scaled versions of rtt and mean deviation.
	 *	This is designed to be as fast as possible
	 *	m stands for "measurement".
	 *
	 *	On a 1990 paper the rto value is changed to:
	 *	RTO = rtt + 4 * mdev
	 *
	 * Funny. This algorithm seems to be very broken.
	 * These formulae increase RTO, when it should be decreased, increase
	 * too slowly, when it should be increased quickly, decrease too quickly
	 * etc. I guess in BSD RTO takes ONE value, so that it is absolutely
	 * does not matter how to _calculate_ it. Seems, it was trap
	 * that VJ failed to avoid. 8)
	 */
	if (m == 0)
		m = 1;
	if (tp->srtt != 0) {
		m -= (tp->srtt >> 3);	/* m is now error in rtt est */
		tp->srtt += m;		/* rtt = 7/8 rtt + 1/8 new */
		if (m < 0) {
			m = -m;		/* m is now abs(error) */
			m -= (tp->mdev >> 2);   /* similar update on mdev */
			/* This is similar to one of Eifel findings.
			 * Eifel blocks mdev updates when rtt decreases.
			 * This solution is a bit different: we use finer gain
			 * for mdev in this case (alpha*beta).
			 * Like Eifel it also prevents growth of rto,
			 * but also it limits too fast rto decreases,
			 * happening in pure Eifel.
			 */
			if (m > 0)
				m >>= 3;
		} else {
			m -= (tp->mdev >> 2);   /* similar update on mdev */
		}
		tp->mdev += m;	    	/* mdev = 3/4 mdev + 1/4 new */
		if (tp->mdev > tp->mdev_max) {
			tp->mdev_max = tp->mdev;
			if (tp->mdev_max > tp->rttvar)
				tp->rttvar = tp->mdev_max;
		}
		if (after(tp->snd_una, tp->rtt_seq)) {
			if (tp->mdev_max < tp->rttvar)
				tp->rttvar -= (tp->rttvar - tp->mdev_max) >> 2;
			tp->rtt_seq = tp->snd_nxt;
			tp->mdev_max = serval_tcp_rto_min(sk);
		}
	} else {
		/* no previous measure. */
		tp->srtt = m << 3;	/* take the measured time to be rtt */
		tp->mdev = m << 1;	/* make sure rto = 3*rtt */
		tp->mdev_max = tp->rttvar = max(tp->mdev, 
                                                serval_tcp_rto_min(sk));
		tp->rtt_seq = tp->snd_nxt;
	}
}
/* Calculate rto without backoff.  This is the second half of Van Jacobson's
 * routine referred to above.
 */
static inline void serval_tcp_set_rto(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	/* Old crap is replaced with new one. 8)
	 *
	 * More seriously:
	 * 1. If rtt variance happened to be less 50msec, it is hallucination.
	 *    It cannot be less due to utterly erratic ACK generation made
	 *    at least by solaris and freebsd. "Erratic ACKs" has _nothing_
	 *    to do with delayed acks, because at cwnd>2 true delack timeout
	 *    is invisible. Actually, Linux-2.4 also generates erratic
	 *    ACKs in some circumstances.
	 */
	tp->rto = __serval_tcp_set_rto(tp);

	/* 2. Fixups made earlier cannot be right.
	 *    If we do not estimate RTO correctly without them,
	 *    all the algo is pure shit and should be replaced
	 *    with correct one. It is exactly, which we pretend to do.
	 */

	/* NOTE: clamping at TCP_RTO_MIN is not required, current algo
	 * guarantees that rto is higher.
	 */
	serval_tcp_bound_rto(sk);
}

static void serval_tcp_valid_rtt_meas(struct sock *sk, u32 seq_rtt)
{
	serval_tcp_rtt_estimator(sk, seq_rtt);
	serval_tcp_set_rto(sk);
	serval_tcp_sk(sk)->backoff = 0;
}


/* If we get here, the whole TSO packet has not been acked. */
static u32 serval_tcp_tso_acked(struct sock *sk, struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
        struct tcphdr *th = tcp_hdr(skb);
	u32 packets_acked;
        u32 seq, end_seq;

        seq = ntohl(th->seq);
        end_seq = (seq + th->syn + th->fin +
                   skb->len - th->doff * 4);

	BUG_ON(!after(TCP_SKB_CB(skb)->end_seq, tp->snd_una));

	packets_acked = serval_tcp_skb_pcount(skb);
	if (serval_tcp_trim_head(sk, skb, tp->snd_una - seq))
		return 0;
	packets_acked -= tcp_skb_pcount(skb);

	if (packets_acked) {
		BUG_ON(tcp_skb_pcount(skb) == 0);
		BUG_ON(!before(seq, end_seq));
	}

	return packets_acked;
}

/* Initialize metrics on socket. */

static void serval_tcp_init_metrics(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct dst_entry *dst = __sk_dst_get(sk);

	if (dst == NULL)
		goto reset;

#if defined(OS_LINUX_KERNEL)
	dst_confirm(dst);

	if (dst_metric_locked(dst, RTAX_CWND))
		tp->snd_cwnd_clamp = dst_metric(dst, RTAX_CWND);
	if (dst_metric(dst, RTAX_SSTHRESH)) {
		tp->snd_ssthresh = dst_metric(dst, RTAX_SSTHRESH);
		if (tp->snd_ssthresh > tp->snd_cwnd_clamp)
			tp->snd_ssthresh = tp->snd_cwnd_clamp;
	}
        /*
	if (dst_metric(dst, RTAX_REORDERING) &&
	    tp->reordering != dst_metric(dst, RTAX_REORDERING)) {
		tcp_disable_fack(tp);
		tp->reordering = dst_metric(dst, RTAX_REORDERING);
	}
        */

	if (dst_metric(dst, RTAX_RTT) == 0)
		goto reset;

	if (!tp->srtt && dst_metric_rtt(dst, RTAX_RTT) < (TCP_TIMEOUT_INIT << 3))
		goto reset;

	/* Initial rtt is determined from SYN,SYN-ACK.
	 * The segment is small and rtt may appear much
	 * less than real one. Use per-dst memory
	 * to make it more realistic.
	 *
	 * A bit of theory. RTT is time passed after "normal" sized packet
	 * is sent until it is ACKed. In normal circumstances sending small
	 * packets force peer to delay ACKs and calculation is correct too.
	 * The algorithm is adaptive and, provided we follow specs, it
	 * NEVER underestimate RTT. BUT! If peer tries to make some clever
	 * tricks sort of "quick acks" for time long enough to decrease RTT
	 * to low value, and then abruptly stops to do it and starts to delay
	 * ACKs, wait for troubles.
	 */
	if (dst_metric_rtt(dst, RTAX_RTT) > tp->srtt) {
		tp->srtt = dst_metric_rtt(dst, RTAX_RTT);
		tp->rtt_seq = tp->snd_nxt;
	}
	if (dst_metric_rtt(dst, RTAX_RTTVAR) > tp->mdev) {
		tp->mdev = dst_metric_rtt(dst, RTAX_RTTVAR);
		tp->mdev_max = tp->rttvar = max(tp->mdev, tcp_rto_min(sk));
	}
#endif
	serval_tcp_set_rto(sk);

	if (tp->rto < TCP_TIMEOUT_INIT && !tp->rx_opt.saw_tstamp)
		goto reset;

cwnd:
	tp->snd_cwnd = serval_tcp_init_cwnd(tp, dst);
	tp->snd_cwnd_stamp = tcp_time_stamp;
	return;

reset:
	/* Play conservative. If timestamps are not
	 * supported, TCP will fail to recalculate correct
	 * rtt, if initial rto is too small. FORGET ALL AND RESET!
	 */
	if (!tp->rx_opt.saw_tstamp && tp->srtt) {
		tp->srtt = 0;
		tp->mdev = tp->mdev_max = tp->rttvar = TCP_TIMEOUT_INIT;
		tp->rto = TCP_TIMEOUT_INIT;
	}
	goto cwnd;
}

/* Read draft-ietf-tcplw-high-performance before mucking
 * with this code. (Supersedes RFC1323)
 */
static void serval_tcp_ack_saw_tstamp(struct sock *sk, int flag)
{
	/* RTTM Rule: A TSecr value received in a segment is used to
	 * update the averaged RTT measurement only if the segment
	 * acknowledges some new data, i.e., only if it advances the
	 * left edge of the send window.
	 *
	 * See draft-ietf-tcplw-high-performance-00, section 3.3.
	 * 1998/04/10 Andrey V. Savochkin <saw@msu.ru>
	 *
	 * Changed: reset backoff as soon as we see the first valid sample.
	 * If we do not, we get strongly overestimated rto. With timestamps
	 * samples are accepted even from very old segments: f.e., when rtt=1
	 * increases to 8, we retransmit 5 times and after 8 seconds delayed
	 * answer arrives rto becomes 120 seconds! If at least one of segments
	 * in window is lost... Voila.	 			--ANK (010210)
	 */
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	serval_tcp_valid_rtt_meas(sk, tcp_time_stamp - tp->rx_opt.rcv_tsecr);
}

static void serval_tcp_ack_no_tstamp(struct sock *sk, u32 seq_rtt, int flag)
{
	/* We don't have a timestamp. Can only use
	 * packets that are not retransmitted to determine
	 * rtt estimates. Also, we must not reset the
	 * backoff for rto until we get a non-retransmitted
	 * packet. This allows us to deal with a situation
	 * where the network delay has increased suddenly.
	 * I.e. Karn's algorithm. (SIGCOMM '87, p5.)
	 */
        
	if (flag & FLAG_RETRANS_DATA_ACKED)
		return;

	serval_tcp_valid_rtt_meas(sk, seq_rtt);
}

static inline void serval_tcp_ack_update_rtt(struct sock *sk, const int flag,
                                             const s32 seq_rtt)
{
	const struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	/* Note that peer MAY send zero echo. In this case it is
         * ignored. (rfc1323) */
	if (tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr)
		serval_tcp_ack_saw_tstamp(sk, flag);
	else if (seq_rtt >= 0)
		serval_tcp_ack_no_tstamp(sk, seq_rtt, flag);
}


static void serval_tcp_ack_probe(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	/* Was it a usable window open? */

	if (!after(TCP_SKB_CB(serval_tcp_send_head(sk))->end_seq, 
                   serval_tcp_wnd_end(tp))) {
		tp->backoff = 0;
		//inet_csk_clear_xmit_timer(sk, ICSK_TIME_PROBE0);
		/* Socket must be waked up by subsequent tcp_data_snd_check().
		 * This function is not for random using!
		 */
	} else {
		/*inet_csk_reset_xmit_timer(sk, ICSK_TIME_PROBE0,
					  min(icsk->icsk_rto << icsk->icsk_backoff, TCP_RTO_MAX),
					  TCP_RTO_MAX);
                */
	}
}

static inline int serval_tcp_ack_is_dubious(const struct sock *sk, 
                                            const int flag)
{
	return (!(flag & FLAG_NOT_DUP) || (flag & FLAG_CA_ALERT) ||
		serval_tcp_sk(sk)->ca_state != TCP_CA_Open);
}

static inline int serval_tcp_may_raise_cwnd(const struct sock *sk, 
                                            const int flag)
{
	const struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	return (!(flag & FLAG_ECE) || tp->snd_cwnd < tp->snd_ssthresh) &&
		!((1 << tp->ca_state) & (TCPF_CA_Recovery | TCPF_CA_CWR));
}

/* Check that window update is acceptable.
 * The function assumes that snd_una<=ack<=snd_next.
 */
static inline int serval_tcp_may_update_window(const struct serval_tcp_sock *tp,
                                               const u32 ack, const u32 ack_seq,
                                               const u32 nwin)
{
	return (after(ack, tp->snd_una) ||
		after(ack_seq, tp->snd_wl1) ||
		(ack_seq == tp->snd_wl1 && nwin > tp->snd_wnd));
}

/* Update our send window.
 *
 * Window update algorithm, described in RFC793/RFC1122 (used in linux-2.2
 * and in FreeBSD. NetBSD's one is even worse.) is wrong.
 */
static int serval_tcp_ack_update_window(struct sock *sk, struct sk_buff *skb, 
                                         u32 ack, u32 ack_seq)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int flag = 0;
	u32 nwin = ntohs(tcp_hdr(skb)->window);

	if (likely(!tcp_hdr(skb)->syn))
		nwin <<= tp->rx_opt.snd_wscale;

	if (serval_tcp_may_update_window(tp, ack, ack_seq, nwin)) {
		flag |= FLAG_WIN_UPDATE;
		serval_tcp_update_wl(tp, ack_seq);

		if (tp->snd_wnd != nwin) {
			tp->snd_wnd = nwin;

			/* Note, it is the only place, where
			 * fast path is recovered for sending TCP.
			 */
			tp->pred_flags = 0;
			serval_tcp_fast_path_check(sk);

			if (nwin > tp->max_window) {
				tp->max_window = nwin;
				serval_tcp_sync_mss(sk, tp->pmtu_cookie);
			}
		}
	}

	tp->snd_una = ack;

	return flag;
}


/* Restart timer after forward progress on connection.
 * RFC2988 recommends to restart timer to now+rto.
 */
static void serval_tcp_rearm_rto(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (!tp->packets_out) {
		//inet_csk_clear_xmit_timer(sk, ICSK_TIME_RETRANS);
	} else {
		//inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
		//			  inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
	}
}

/*
 * Packet counting of FACK is based on in-order assumptions, therefore TCP
 * disables it when reordering is detected
 */
static void serval_tcp_disable_fack(struct serval_tcp_sock *tp)
{
	/* RFC3517 uses different metric in lost marker => reset on change */
        /*
	if (serval_tcp_is_fack(tp))
		tp->lost_skb_hint = NULL;
        */
	tp->rx_opt.sack_ok &= ~2;
}

static void serval_tcp_update_reordering(struct sock *sk, const int metric,
                                         const int ts)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	if (metric > tp->reordering) {
		//int mib_idx;

		tp->reordering = min(TCP_MAX_REORDERING, metric);

		/* This exciting event is worth to be remembered. 8) */
                /*
		if (ts)
			mib_idx = LINUX_MIB_TCPTSREORDER;
		else if (tcp_is_reno(tp))
			mib_idx = LINUX_MIB_TCPRENOREORDER;
		else if (tcp_is_fack(tp))
			mib_idx = LINUX_MIB_TCPFACKREORDER;
		else
			mib_idx = LINUX_MIB_TCPSACKREORDER;

		NET_INC_STATS_BH(sock_net(sk), mib_idx);
                */

#if FASTRETRANS_DEBUG > 1
		printk(KERN_DEBUG "Disorder%d %d %u f%u s%u rr%d\n",
		       tp->rx_opt.sack_ok, inet_csk(sk)->icsk_ca_state,
		       tp->reordering,
		       tp->fackets_out,
		       tp->sacked_out,
		       tp->undo_marker ? tp->undo_retrans : 0);
#endif
		serval_tcp_disable_fack(tp);
	}
}


/* Limits sacked_out so that sum with lost_out isn't ever larger than
 * packets_out. Returns zero if sacked_out adjustement wasn't necessary.
 */
static int serval_tcp_limit_reno_sacked(struct serval_tcp_sock *tp)
{
	u32 holes;

	holes = max(tp->lost_out, 1U);
	holes = min(holes, tp->packets_out);

	if ((tp->sacked_out + holes) > tp->packets_out) {
		tp->sacked_out = tp->packets_out - holes;
		return 1;
	}
	return 0;
}

/* If we receive more dupacks than we expected counting segments
 * in assumption of absent reordering, interpret this as reordering.
 * The only another reason could be bug in receiver TCP.
 */
static void serval_tcp_check_reno_reordering(struct sock *sk, const int addend)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	if (serval_tcp_limit_reno_sacked(tp))
		serval_tcp_update_reordering(sk, tp->packets_out + addend, 0);
}


/* Account for ACK, ACKing some data in Reno Recovery phase. */
static void serval_tcp_remove_reno_sacks(struct sock *sk, int acked)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (acked > 0) {
		/* One ACK acked hole. The rest eat duplicate ACKs. */
		if (acked - 1 >= tp->sacked_out)
			tp->sacked_out = 0;
		else
			tp->sacked_out -= acked - 1;
	}
	serval_tcp_check_reno_reordering(sk, acked);
	serval_tcp_verify_left_out(tp);
}

/* Remove acknowledged frames from the retransmission queue. If our packet
 * is before the ack sequence we can discard it as it's confirmed to have
 * arrived at the other end.
 */
static int serval_tcp_clean_rtx_queue(struct sock *sk, int prior_fackets,
                                      u32 prior_snd_una)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *skb;
	u32 now = tcp_time_stamp;
	int fully_acked = 1;
	int flag = 0;
	u32 pkts_acked = 0;
	u32 reord = tp->packets_out;
	//u32 prior_sacked = tp->sacked_out;
	s32 seq_rtt = -1;
	s32 ca_seq_rtt = -1;
#if defined(OS_LINUX_KERNEL)
	ktime_t last_ackt = net_invalid_timestamp();
#endif

	while ((skb = serval_tcp_write_queue_head(sk)) && 
               skb != serval_tcp_send_head(sk)) {
		struct tcp_skb_cb *scb = TCP_SKB_CB(skb);
		u32 acked_pcount;
		u8 sacked = scb->sacked;

		/* Determine how many packets and what bytes were
                 * acked, tso and else */
		if (after(scb->end_seq, tp->snd_una)) {
			if (serval_tcp_skb_pcount(skb) == 1 ||
			    !after(tp->snd_una, scb->seq))
				break;

			acked_pcount = serval_tcp_tso_acked(sk, skb);
			if (!acked_pcount)
				break;

			fully_acked = 0;
		} else {
			acked_pcount = serval_tcp_skb_pcount(skb);
		}

		if (sacked & TCPCB_RETRANS) {
			if (sacked & TCPCB_SACKED_RETRANS)
				tp->retrans_out -= acked_pcount;
			flag |= FLAG_RETRANS_DATA_ACKED;
			ca_seq_rtt = -1;
			seq_rtt = -1;
			if ((flag & FLAG_DATA_ACKED) || (acked_pcount > 1))
				flag |= FLAG_NONHEAD_RETRANS_ACKED;
		} else {
			ca_seq_rtt = now - scb->when;

#if defined(OS_LINUX_KERNEL)
			last_ackt = skb->tstamp;
#endif
			if (seq_rtt < 0) {
				seq_rtt = ca_seq_rtt;
			}
			if (!(sacked & TCPCB_SACKED_ACKED))
				reord = min(pkts_acked, reord);
		}

		if (sacked & TCPCB_SACKED_ACKED)
			tp->sacked_out -= acked_pcount;
		if (sacked & TCPCB_LOST)
			tp->lost_out -= acked_pcount;

		tp->packets_out -= acked_pcount;
		pkts_acked += acked_pcount;

		/* Initial outgoing SYN's get put onto the write_queue
		 * just like anything else we transmit.  It is not
		 * true data, and if we misinform our callers that
		 * this ACK acks real data, we will erroneously exit
		 * connection startup slow start one packet too
		 * quickly.  This is severely frowned upon behavior.
		 */
		if (!(scb->flags & TCPH_SYN)) {
			flag |= FLAG_DATA_ACKED;
		} else {
			flag |= FLAG_SYN_ACKED;
			tp->retrans_stamp = 0;
		}

		if (!fully_acked)
			break;

		serval_tcp_unlink_write_queue(skb, sk);
		sk_wmem_free_skb(sk, skb);
                /*
		tp->scoreboard_skb_hint = NULL;
		if (skb == tp->retransmit_skb_hint)
			tp->retransmit_skb_hint = NULL;
		if (skb == tp->lost_skb_hint)
			tp->lost_skb_hint = NULL;
                */
	}

	if (likely(between(tp->snd_up, prior_snd_una, tp->snd_una)))
		tp->snd_up = tp->snd_una;

	if (skb && (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED))
		flag |= FLAG_SACK_RENEGING;

	if (flag & FLAG_ACKED) {
		const struct tcp_congestion_ops *ca_ops
			= tp->ca_ops;

                /*
		if (unlikely(tp->tp_mtup.probe_size &&
			     !after(tp->mtu_probe.probe_seq_end, tp->snd_una))) {
			serval_tcp_mtup_probe_success(sk);
		}
                */

		serval_tcp_ack_update_rtt(sk, flag, seq_rtt);
		serval_tcp_rearm_rto(sk);

		if (serval_tcp_is_reno(tp)) {
			serval_tcp_remove_reno_sacks(sk, pkts_acked);
		} else {
                        LOG_WARN("Only TCP RENO supported!\n");
                        /*
			int delta;

			if (reord < prior_fackets)
				serval_tcp_update_reordering(sk, tp->fackets_out - reord, 0);

			delta = tcp_is_fack(tp) ? pkts_acked :
						  prior_sacked - tp->sacked_out;
			tp->lost_cnt_hint -= min(tp->lost_cnt_hint, delta);
                        */
		}

		tp->fackets_out -= min(pkts_acked, tp->fackets_out);

		if (ca_ops->pkts_acked) {
			s32 rtt_us = -1;

			/* Is the ACK triggering packet unambiguous? */
			if (!(flag & FLAG_RETRANS_DATA_ACKED)) {
				/* High resolution needed and available? */
#if defined(OS_LINUX_KERNEL)
				if (ca_ops->flags & TCP_CONG_RTT_STAMP &&
				    !ktime_equal(last_ackt,
						 net_invalid_timestamp()))
					rtt_us = ktime_us_delta(ktime_get_real(),
								last_ackt);
				else 
#endif
                                        if (ca_seq_rtt > 0)
                                                rtt_us = jiffies_to_usecs(ca_seq_rtt);
			}

			ca_ops->pkts_acked(sk, pkts_acked, rtt_us);
		}
	}

	return flag;
}


static void serval_tcp_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	tp->ca_ops->cong_avoid(sk, ack, in_flight);
	tp->snd_cwnd_stamp = tcp_time_stamp;
}

/* This routine deals with incoming acks, but not outgoing ones. */
static int serval_tcp_ack(struct sock *sk, struct sk_buff *skb, int flag)
{
	//struct inet_connection_sock *icsk = inet_csk(sk);
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	u32 prior_snd_una = tp->snd_una;
	u32 ack_seq = ntohl(tcp_hdr(skb)->seq); //TCP_SKB_CB(skb)->seq;
	u32 ack = ntohl(tcp_hdr(skb)->ack_seq); //TCP_SKB_CB(skb)->ack_seq;
	u32 prior_in_flight;
	u32 prior_fackets;
	int prior_packets;
	int frto_cwnd = 0;

	/* If the ack is older than previous acks
	 * then we can probably ignore it.
	 */
	if (before(ack, prior_snd_una))
		goto old_ack;

	/* If the ack includes data we haven't sent yet, discard
	 * this segment (RFC793 Section 3.9).
	 */
	if (after(ack, tp->snd_nxt))
		goto invalid_ack;

	if (after(ack, prior_snd_una))
		flag |= FLAG_SND_UNA_ADVANCED;

	if (sysctl_serval_tcp_abc) {
		if (tp->ca_state < TCP_CA_CWR)
			tp->bytes_acked += ack - prior_snd_una;
		else if (tp->ca_state == TCP_CA_Loss)
			/* we assume just one segment left network */
			tp->bytes_acked += min(ack - prior_snd_una,
					       tp->mss_cache);
	}

	prior_fackets = tp->fackets_out;
	prior_in_flight = serval_tcp_packets_in_flight(tp);

	if (!(flag & FLAG_SLOWPATH) && after(ack, prior_snd_una)) {
		/* Window is constant, pure forward advance.
		 * No more checks are required.
		 * Note, we use the fact that SND.UNA>=SND.WL2.
		 */
		serval_tcp_update_wl(tp, ack_seq);
		tp->snd_una = ack;
		flag |= FLAG_WIN_UPDATE;

		serval_tcp_ca_event(sk, CA_EVENT_FAST_ACK);

		//NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPHPACKS);
	} else {
		if (ack_seq != TCP_SKB_CB(skb)->end_seq)
			flag |= FLAG_DATA;
                /*
		else
			NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPPUREACKS);
                */
		flag |= serval_tcp_ack_update_window(sk, skb, ack, ack_seq);

                /*
		if (TCP_SKB_CB(skb)->sacked)
			flag |= tcp_sacktag_write_queue(sk, skb, prior_snd_una);

		if (TCP_ECN_rcv_ecn_echo(tp, tcp_hdr(skb)))
			flag |= FLAG_ECE;
                */

		serval_tcp_ca_event(sk, CA_EVENT_SLOW_ACK);
	}

	/* We passed data and got it acked, remove any soft error
	 * log. Something worked...
	 */
	sk->sk_err_soft = 0;
	tp->probes_out = 0;
	tp->rcv_tstamp = tcp_time_stamp;
	prior_packets = tp->packets_out;
	if (!prior_packets)
		goto no_queue;

	/* See if we can take anything off of the retransmit queue. */
	flag |= serval_tcp_clean_rtx_queue(sk, prior_fackets, prior_snd_una);

#if defined(FRTO)        
	if (tp->frto_counter)
		frto_cwnd = serval_tcp_process_frto(sk, flag);

	/* Guarantee sacktag reordering detection against wrap-arounds */
	if (before(tp->frto_highmark, tp->snd_una))
		tp->frto_highmark = 0;
#endif
	if (serval_tcp_ack_is_dubious(sk, flag)) {
		/* Advance CWND, if state allows this. */
		if ((flag & FLAG_DATA_ACKED) && !frto_cwnd &&
		    serval_tcp_may_raise_cwnd(sk, flag))
			serval_tcp_cong_avoid(sk, ack, prior_in_flight);

                LOG_WARN("No fast retransmission alert implemented!\n");
		/*serval_tcp_fastretrans_alert(sk, prior_packets - 
                                             tp->packets_out, flag);
                */
	} else {
		if ((flag & FLAG_DATA_ACKED) && !frto_cwnd)
			serval_tcp_cong_avoid(sk, ack, prior_in_flight);
	}

#if defined(OS_LINUX_KERNEL)
	if ((flag & FLAG_FORWARD_PROGRESS) || !(flag & FLAG_NOT_DUP))
		dst_confirm(__sk_dst_get(sk));
#endif
	return 1;

no_queue:
	/* If this ack opens up a zero window, clear backoff.  It was
	 * being used to time the probes, and is probably far higher than
	 * it needs to be for normal retransmission.
	 */
	if (serval_tcp_send_head(sk))
		serval_tcp_ack_probe(sk);
	return 1;

invalid_ack:
	//SOCK_DEBUG(sk, "Ack %u after %u:%u\n", ack, tp->snd_una, tp->snd_nxt);
	return -1;

old_ack:
        /*
	if (TCP_SKB_CB(skb)->sacked) {
		tcp_sacktag_write_queue(sk, skb, prior_snd_una);
		if (icsk->icsk_ca_state == TCP_CA_Open)
			tcp_try_keep_open(sk);
	}
        */

	//SOCK_DEBUG(sk, "Ack %u before %u:%u\n", ack, tp->snd_una, tp->snd_nxt);
	return 0;
}

/* 
 */
int serval_tcp_syn_recv_state_process(struct sock *sk, struct sk_buff *skb)
{
        struct tcphdr *th;
        struct serval_tcp_sock *tp = serval_tcp_sk(sk);
        u32 ack_seq, seq;

        if (!pskb_may_pull(skb, sizeof(struct tcphdr))) {
                LOG_ERR("No TCP header?\n");
                FREE_SKB(skb);
                return -1;
        }

        th = tcp_hdr(skb);
        ack_seq = ntohl(th->ack_seq);
        seq = ntohl(th->seq);

        LOG_DBG("TCP ACK seq=%u ackno=%u\n", seq, ack_seq);

	tp->copied_seq = tp->rcv_nxt;
#if defined(OS_LINUX_KERNEL)
        smp_mb();
#endif
     
	if (th->ack) {
		int acceptable = serval_tcp_ack(sk, skb, FLAG_SLOWPATH) > 0;

                if (!acceptable)
                        return 1;
                
                LOG_DBG("ACK is acceptable!\n");

                tp->snd_una = ack_seq;
                tp->snd_wnd = ntohs(th->window) <<
                                tp->rx_opt.snd_wscale;
                
                serval_tcp_init_wl(tp, seq);
                
                /* tcp_ack considers this ACK as duplicate
                 * and does not calculate rtt.
                 * Force it here.
                 */
                serval_tcp_ack_update_rtt(sk, 0, 0);
                
                /*
                  if (tp->rx_opt.tstamp_ok)
                  tp->advmss -= TCPOLEN_TSTAMP_ALIGNED;
                */
                
                /* Make sure socket is routed, for
                 * correct metrics.
                 */
                //icsk->icsk_af_ops->rebuild_header(sk);
                
                serval_tcp_init_metrics(sk);
                
                serval_tcp_init_congestion_control(sk);
                
                /* Prevent spurious tcp_cwnd_restart() on
                 * first data packet.
                 */
                tp->lsndtime = tcp_time_stamp;
                
                // serval_tcp_mtup_init(sk);
                serval_tcp_initialize_rcv_mss(sk);
                serval_tcp_init_buffer_space(sk);
                serval_tcp_fast_path_on(tp);
        } else {
                LOG_WARN("No ACK flag in packet!\n");
        }
        return 0;
}

int serval_tcp_syn_sent_state_process(struct sock *sk, struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
        struct tcphdr *th = tcp_hdr(skb);
	int saved_clamp = tp->rx_opt.mss_clamp;
        u32 seq = ntohl(th->seq);

        if (th->ack) {
                LOG_DBG("ACK received\n");

		/* rfc793:
		 * "If the state is SYN-SENT then
		 *    first check the ACK bit
		 *      If the ACK bit is set
		 *	  If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send
		 *        a reset (unless the RST bit is set, if so drop
		 *        the segment and return)"
		 *
		 *  We do not send data with SYN, so that RFC-correct
		 *  test reduces to:
		 */
		if (ntohl(th->ack_seq) != tp->snd_nxt)
			goto reset_and_undo;

		tp->snd_wl1 = seq;
		serval_tcp_ack(sk, skb, FLAG_SLOWPATH);

		/* Ok.. it's good. Set up sequence numbers and
		 * move to established.
		 */
		tp->rcv_nxt = seq + 1;
		tp->rcv_wup = seq + 1;

		/* RFC1323: The window in SYN & SYN/ACK segments is
		 * never scaled.
		 */
		tp->snd_wnd = ntohs(th->window);
		serval_tcp_init_wl(tp, seq);

		if (!tp->rx_opt.wscale_ok) {
			tp->rx_opt.snd_wscale = tp->rx_opt.rcv_wscale = 0;
			tp->window_clamp = min(tp->window_clamp, 65535U);
		}

                /*
		if (tp->rx_opt.saw_tstamp) {
			tp->rx_opt.tstamp_ok	   = 1;
			tp->tcp_header_len =
				sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED;
			tp->advmss	    -= TCPOLEN_TSTAMP_ALIGNED;
			tcp_store_ts_recent(tp);
		} else {
			tp->tcp_header_len = sizeof(struct tcphdr);
		}
                */

                /*
		if (tcp_is_sack(tp) && sysctl_tcp_fack)
			tcp_enable_fack(tp);
                */

		//serval_tcp_mtup_init(sk);
		serval_tcp_sync_mss(sk, tp->pmtu_cookie);
		serval_tcp_initialize_rcv_mss(sk);

		/* Remember, tcp_poll() does not lock socket!
		 * Change state from SYN-SENT only after copied_seq
		 * is initialized. */
		tp->copied_seq = tp->rcv_nxt;

        }
        
        return 0;
        
reset_and_undo:
        FREE_SKB(skb);
	tp->rx_opt.mss_clamp = saved_clamp;
        return -1;
}
