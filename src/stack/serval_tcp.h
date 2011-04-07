#ifndef _SERVAL_TCP_H_
#define _SERVAL_TCP_H_

#include <serval/platform.h>
#include <serval_tcp_sock.h>

#if defined(OS_LINUX_KERNEL)
#include <net/tcp.h>
#endif

#if defined(OS_USER)
#include <userlevel/serval_tcp_user.h>
#endif /* OS_USER */


/* TCP timestamps are only 32-bits, this causes a slight
 * complication on 64-bit systems since we store a snapshot
 * of jiffies in the buffer control blocks below.  We decided
 * to use only the low 32-bits of jiffies and hide the ugly
 * casts with the following macro.
 */
#define tcp_time_stamp		((__u32)(jiffies))


#define EXTRA_HDR (20)

/* payload + LL + IP + extra */
#define MAX_SERVAL_TCP_HEADER (MAX_HEADER + 20 + EXTRA_HDR +        \
                               sizeof(struct serval_hdr) +          \
                               sizeof(struct serval_service_ext) +  \
                               sizeof(struct tcphdr))


/* 
 * Never offer a window over 32767 without using window scaling. Some
 * poor stacks do signed 16bit maths! 
 */
#define MAX_TCP_WINDOW		32767U

/* Minimal accepted MSS. It is (60+60+8) - (20+20). */
#define TCP_MIN_MSS		88U

/* The least MTU to use for probing */
#define TCP_BASE_MSS		512

/* After receiving this amount of duplicate ACKs fast retransmit starts. */
#define TCP_FASTRETRANS_THRESH 3

/* Maximal reordering. */
#define TCP_MAX_REORDERING	127

/* Maximal number of ACKs sent quickly to accelerate slow-start. */
#define TCP_MAX_QUICKACKS	16U

/* urg_data states */
#define TCP_URG_VALID	0x0100
#define TCP_URG_NOTYET	0x0200
#define TCP_URG_READ	0x0400

#define TCP_RETR1	3	/*
				 * This is how many retries it does before it
				 * tries to figure out if the gateway is
				 * down. Minimal RFC value is 3; it corresponds
				 * to ~3sec-8min depending on RTO.
				 */

#define TCP_RETR2	15	/*
				 * This should take at least
				 * 90 minutes to time out.
				 * RFC1122 says that the limit is 100 sec.
				 * 15 is ~13-30min depending on RTO.
				 */

#define TCP_SYN_RETRIES	 5	/* number of times to retry active opening a
				 * connection: ~180sec is RFC minimum	*/

#define TCP_SYNACK_RETRIES 5	/* number of times to retry passive opening a
				 * connection: ~180sec is RFC minimum	*/


#define TCP_ORPHAN_RETRIES 7	/* number of times to retry on an orphaned
				 * socket. 7 is ~50sec-16min.
				 */


#define TCP_TIMEWAIT_LEN (60*HZ) /* how long to wait to destroy TIME-WAIT
				  * state, about 60 seconds	*/
#define TCP_FIN_TIMEOUT	TCP_TIMEWAIT_LEN
                                 /* BSD style FIN_WAIT2 deadlock breaker.
				  * It used to be 3min, new value is 60sec,
				  * to combine FIN-WAIT-2 timeout with
				  * TIME-WAIT timer.
				  */

#define TCP_DELACK_MAX	((unsigned)(HZ/5))	/* maximal time to delay before sending an ACK */
#if HZ >= 100
#define TCP_DELACK_MIN	((unsigned)(HZ/25))	/* minimal time to delay before sending an ACK */
#define TCP_ATO_MIN	((unsigned)(HZ/25))
#else
#define TCP_DELACK_MIN	4U
#define TCP_ATO_MIN	4U
#endif
#define TCP_RTO_MAX	((unsigned)(120*HZ))
#define TCP_RTO_MIN	((unsigned)(HZ/5))
#define TCP_TIMEOUT_INIT ((unsigned)(3*HZ))	/* RFC 1122 initial RTO value	*/

#define TCP_RESOURCE_PROBE_INTERVAL ((unsigned)(HZ/2U)) /* Maximal interval between probes
					                 * for local resources.
					                 */

#define TCP_KEEPALIVE_TIME	(120*60*HZ)	/* two hours */
#define TCP_KEEPALIVE_PROBES	9		/* Max of 9 keepalive probes	*/
#define TCP_KEEPALIVE_INTVL	(75*HZ)

#define MAX_TCP_KEEPIDLE	32767
#define MAX_TCP_KEEPINTVL	32767
#define MAX_TCP_KEEPCNT		127
#define MAX_TCP_SYNCNT		127

#define TCP_SYNQ_INTERVAL	(HZ/5)	/* Period of SYNACK timer */

#define TCP_PAWS_24DAYS	(60 * 60 * 24 * 24)
#define TCP_PAWS_MSL	60		/* Per-host timestamps are invalidated
					 * after this time. It should be equal
					 * (or greater than) TCP_TIMEWAIT_LEN
					 * to provide reliability equal to one
					 * provided by timewait state.
					 */
#define TCP_PAWS_WINDOW	1		/* Replay window for per-host
					 * timestamps. It must be less than
					 * minimal timewait lifetime.
					 */

/* write queue abstraction */
static inline void serval_tcp_write_queue_purge(struct sock *sk)
{
	struct sk_buff *skb;

	while ((skb = __skb_dequeue(&sk->sk_write_queue)) != NULL)
		sk_wmem_free_skb(sk, skb);
	sk_mem_reclaim(sk);
	//serval_tcp_clear_all_retrans_hints(tcp_sk(sk));
}

static inline struct sk_buff *serval_tcp_write_queue_head(struct sock *sk)
{
	return skb_peek(&sk->sk_write_queue);
}

static inline struct sk_buff *serval_tcp_write_queue_tail(struct sock *sk)
{
	return skb_peek_tail(&sk->sk_write_queue);
}

static inline struct sk_buff *serval_tcp_write_queue_next(struct sock *sk, 
						   struct sk_buff *skb)
{
	return skb_queue_next(&sk->sk_write_queue, skb);
}

static inline struct sk_buff *serval_tcp_write_queue_prev(struct sock *sk, 
						   struct sk_buff *skb)
{
	return skb_queue_prev(&sk->sk_write_queue, skb);
}

#define serval_tcp_for_write_queue(skb, sk)					\
	skb_queue_walk(&(sk)->sk_write_queue, skb)

#define serval_tcp_for_write_queue_from(skb, sk)				\
	skb_queue_walk_from(&(sk)->sk_write_queue, skb)

#define serval_tcp_for_write_queue_from_safe(skb, tmp, sk)			\
	skb_queue_walk_from_safe(&(sk)->sk_write_queue, skb, tmp)

static inline struct sk_buff *serval_tcp_send_head(struct sock *sk)
{
	return sk->sk_send_head;
}

static inline int serval_tcp_skb_is_last(const struct sock *sk,
				  const struct sk_buff *skb)
{
	return skb_queue_is_last(&sk->sk_write_queue, skb);
}

static inline void serval_tcp_advance_send_head(struct sock *sk, struct sk_buff *skb)
{
	if (serval_tcp_skb_is_last(sk, skb))
		sk->sk_send_head = NULL;
	else
		sk->sk_send_head = serval_tcp_write_queue_next(sk, skb);
}

static inline void serval_tcp_check_send_head(struct sock *sk, struct sk_buff *skb_unlinked)
{
	if (sk->sk_send_head == skb_unlinked)
		sk->sk_send_head = NULL;
}

static inline void serval_tcp_init_send_head(struct sock *sk)
{
	sk->sk_send_head = NULL;
}

static inline void __serval_tcp_add_write_queue_tail(struct sock *sk, struct sk_buff *skb)
{
	__skb_queue_tail(&sk->sk_write_queue, skb);
}

static inline void serval_tcp_add_write_queue_tail(struct sock *sk, struct sk_buff *skb)
{
	__serval_tcp_add_write_queue_tail(sk, skb);

	/* Queue it, remembering where we must start sending. */
	if (sk->sk_send_head == NULL) {
		sk->sk_send_head = skb;
		/*
		if (tcp_sk(sk)->highest_sack == NULL)
			tcp_sk(sk)->highest_sack = skb;
		*/
	}
}

static inline void __serval_tcp_add_write_queue_head(struct sock *sk, struct sk_buff *skb)
{
	__skb_queue_head(&sk->sk_write_queue, skb);
}

/* Insert buff after skb on the write queue of sk.  */
static inline void serval_tcp_insert_write_queue_after(struct sk_buff *skb,
						struct sk_buff *buff,
						struct sock *sk)
{
	__skb_queue_after(&sk->sk_write_queue, skb, buff);
}

/* Insert new before skb on the write queue of sk.  */
static inline void serval_tcp_insert_write_queue_before(struct sk_buff *new,
						  struct sk_buff *skb,
						  struct sock *sk)
{
	__skb_queue_before(&sk->sk_write_queue, skb, new);

	if (sk->sk_send_head == skb)
		sk->sk_send_head = new;
}

static inline void serval_tcp_unlink_write_queue(struct sk_buff *skb, struct sock *sk)
{
	__skb_unlink(skb, &sk->sk_write_queue);
}

static inline int serval_tcp_write_queue_empty(struct sock *sk)
{
	return skb_queue_empty(&sk->sk_write_queue);
}

static inline void serval_tcp_push_pending_frames(struct sock *sk)
{
	if (serval_tcp_send_head(sk)) {
		/*
		struct tcp_sock *tp = tcp_sk(sk);

		__tcp_push_pending_frames(sk, tcp_current_mss(sk), tp->nonagle);
		*/
	}
}

void serval_tcp_rcv_space_adjust(struct sock *sk);


/* Compute the actual receive window we are currently advertising.
 * Rcv_nxt can be after the window if our peer push more data
 * than the offered window.
 */
static inline u32 serval_tcp_receive_window(const struct serval_tcp_sock *tp)
{
	s32 win = tp->rcv_wup + tp->rcv_wnd - tp->rcv_nxt;

	if (win < 0)
		win = 0;
	return (u32) win;
}

/* Choose a new window, without checks for shrinking, and without
 * scaling applied to the result.  The caller does these things
 * if necessary.  This is a "raw" window selection.
 */
u32 __serval_tcp_select_window(struct sock *sk);

void __serval_tcp_push_pending_frames(struct sock *sk, unsigned int cur_mss,
                                      int nonagle);
void serval_tcp_push_one(struct sock *sk, unsigned int mss_now);

static inline int serval_tcp_win_from_space(int space)
{
	return sysctl_tcp_adv_win_scale<=0 ?
		(space>>(-sysctl_tcp_adv_win_scale)) :
		space - (space>>sysctl_tcp_adv_win_scale);
}

/* Note: caller must be prepared to deal with negative returns */ 
static inline int serval_tcp_space(const struct sock *sk)
{
	return serval_tcp_win_from_space(sk->sk_rcvbuf -
					 atomic_read(&sk->sk_rmem_alloc));
} 

static inline int serval_tcp_full_space(const struct sock *sk)
{
	return serval_tcp_win_from_space(sk->sk_rcvbuf); 
}


/* sysctl variables for tcp */
extern int sysctl_tcp_timestamps;
extern int sysctl_tcp_window_scaling;
extern int sysctl_tcp_sack;
extern int sysctl_tcp_fin_timeout;
extern int sysctl_tcp_keepalive_time;
extern int sysctl_tcp_keepalive_probes;
extern int sysctl_tcp_keepalive_intvl;
extern int sysctl_tcp_syn_retries;
extern int sysctl_tcp_synack_retries;
extern int sysctl_tcp_retries1;
extern int sysctl_tcp_retries2;
extern int sysctl_tcp_orphan_retries;
extern int sysctl_tcp_syncookies;
extern int sysctl_tcp_retrans_collapse;
extern int sysctl_tcp_stdurg;
extern int sysctl_tcp_rfc1337;
extern int sysctl_tcp_abort_on_overflow;
extern int sysctl_tcp_max_orphans;
extern int sysctl_tcp_fack;
extern int sysctl_tcp_reordering;
extern int sysctl_tcp_ecn;
extern int sysctl_tcp_dsack;
extern int sysctl_tcp_mem[3];
extern int sysctl_tcp_wmem[3];
extern int sysctl_tcp_rmem[3];
extern int sysctl_tcp_app_win;
extern int sysctl_tcp_adv_win_scale;
extern int sysctl_tcp_tw_reuse;
extern int sysctl_tcp_frto;
extern int sysctl_tcp_frto_response;
extern int sysctl_tcp_low_latency;
extern int sysctl_tcp_dma_copybreak;
extern int sysctl_tcp_nometrics_save;
extern int sysctl_tcp_moderate_rcvbuf;
extern int sysctl_tcp_tso_win_divisor;
extern int sysctl_tcp_abc;
extern int sysctl_tcp_mtu_probing;
extern int sysctl_tcp_base_mss;
extern int sysctl_tcp_workaround_signed_windows;
extern int sysctl_tcp_slow_start_after_idle;
extern int sysctl_tcp_max_ssthresh;
extern int sysctl_tcp_cookie_size;
extern int sysctl_tcp_thin_linear_timeouts;
extern int sysctl_tcp_thin_dupack;

extern atomic_t tcp_memory_allocated;
extern int tcp_memory_pressure;

static inline void __serval_tcp_fast_path_on(struct serval_tcp_sock *tp, 
					     u32 snd_wnd)
{
	tp->pred_flags = htonl((tp->tcp_header_len << 26) |
			       ntohl(TCP_FLAG_ACK) |
			       snd_wnd);
}

static inline void serval_tcp_fast_path_on(struct serval_tcp_sock *tp)
{
	__serval_tcp_fast_path_on(tp, tp->snd_wnd >> tp->rx_opt.snd_wscale);
}

static inline void serval_tcp_fast_path_check(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (skb_queue_empty(&tp->out_of_order_queue) &&
	    tp->rcv_wnd &&
	    atomic_read(&sk->sk_rmem_alloc) < sk->sk_rcvbuf &&
	    !tp->urg_data)
		serval_tcp_fast_path_on(tp);
}

static inline void serval_tcp_check_probe_timer(struct sock *sk)
{
	/*
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);


	if (!tp->packets_out && !icsk->icsk_pending)
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_PROBE0,
					  icsk->icsk_rto, TCP_RTO_MAX);
	*/
}

#endif /* _SERVAL_TCP_H_ */
