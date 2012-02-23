/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SERVAL_TCP_USER_H_
#define _SERVAL_TCP_USER_H_

#if defined(OS_LINUX)
#include <netinet/tcp.h>
#endif
#include <serval/request_sock.h>

/* Flags in tp->nonagle */
#define TCP_NAGLE_OFF		1	/* Nagle's algo is disabled */
#define TCP_NAGLE_CORK		2	/* Socket is corked	    */
#define TCP_NAGLE_PUSH		4	/* Cork is overridden for already queued data */

static inline int before(__u32 seq1, __u32 seq2)
{
        return (__s32)(seq1-seq2) < 0;
}
#define after(seq2, seq1) 	before(seq1, seq2)

/* is s2<=s1<=s3 ? */
static inline int between(__u32 seq1, __u32 seq2, __u32 seq3)
{
	return seq3 - seq2 >= seq1 - seq2;
}

/* From net/tcp_states.h */
#define TCP_STATE_MASK	0xF

#define TCP_ACTION_FIN	(1 << 7)

enum {
	TCPF_ESTABLISHED = (1 << 1),
	TCPF_SYN_SENT	 = (1 << 2),
	TCPF_SYN_RECV	 = (1 << 3),
	TCPF_FIN_WAIT1	 = (1 << 4),
	TCPF_FIN_WAIT2	 = (1 << 5),
	TCPF_TIME_WAIT	 = (1 << 6),
	TCPF_CLOSE	 = (1 << 7),
	TCPF_CLOSE_WAIT	 = (1 << 8),
	TCPF_LAST_ACK	 = (1 << 9),
	TCPF_LISTEN	 = (1 << 10),
	TCPF_CLOSING	 = (1 << 11) 
};

/* END net/tcp_states.h */

struct inet_skb_parm {
        struct ip_options       opt;     /* Compiled IP options          */
        unsigned char           flags;

#define IPSKB_FORWARDED         1
#define IPSKB_XFRM_TUNNEL_SIZE  2
#define IPSKB_XFRM_TRANSFORMED  4
#define IPSKB_FRAG_COMPLETE     8
#define IPSKB_REROUTED          16
};

/* This is what the send packet queuing engine uses to pass
 * TCP per-packet control information to the transmission
 * code.  We also store the host-order sequence numbers in
 * here too.  This is 36 bytes on 32-bit architectures,
 * 40 bytes on 64-bit machines, if this grows please adjust
 * skbuff.h:skbuff->cb[xxx] size appropriately.
 */
struct tcp_skb_cb {
	union {
		struct inet_skb_parm	h4;
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
		struct inet6_skb_parm	h6;
#endif
	} header;	/* For incoming frames		*/
	uint32_t	seq;		/* Starting sequence number	*/
	uint32_t	end_seq;	/* SEQ + FIN + SYN + datalen	*/
	uint32_t	when;		/* used to compute rtt's	*/
	uint8_t		tcp_flags;	/* TCP header flags.		*/

	/* NOTE: These must match up to the flags byte in a
	 *       real TCP header.
	 */
#define TCPCB_FLAG_FIN		0x01
#define TCPCB_FLAG_SYN		0x02
#define TCPCB_FLAG_RST		0x04
#define TCPCB_FLAG_PSH		0x08
#define TCPCB_FLAG_ACK		0x10
#define TCPCB_FLAG_URG		0x20
#define TCPCB_FLAG_ECE		0x40
#define TCPCB_FLAG_CWR		0x80

	uint8_t		sacked;		/* State flags for SACK/FACK.	*/
#define TCPCB_SACKED_ACKED	0x01	/* SKB ACK'd by a SACK block	*/
#define TCPCB_SACKED_RETRANS	0x02	/* SKB retransmitted		*/
#define TCPCB_LOST		0x04	/* SKB is lost			*/
#define TCPCB_TAGBITS		0x07	/* All tag bits			*/

#define TCPCB_EVER_RETRANS	0x80	/* Ever retransmitted frame	*/
#define TCPCB_RETRANS		(TCPCB_SACKED_RETRANS|TCPCB_EVER_RETRANS)

	uint32_t	ack_seq;	/* Sequence number ACK'd	*/
};

#if defined(OS_BSD)
#define __cpu_to_be32(n) htonl(n)
#endif

enum { 
	TCP_FLAG_CWR = __cpu_to_be32(0x00800000),
	TCP_FLAG_ECE = __cpu_to_be32(0x00400000),
	TCP_FLAG_URG = __cpu_to_be32(0x00200000),
	TCP_FLAG_ACK = __cpu_to_be32(0x00100000),
	TCP_FLAG_PSH = __cpu_to_be32(0x00080000),
	TCP_FLAG_RST = __cpu_to_be32(0x00040000),
	TCP_FLAG_SYN = __cpu_to_be32(0x00020000),
	TCP_FLAG_FIN = __cpu_to_be32(0x00010000),
	TCP_RESERVED_BITS = __cpu_to_be32(0x0F000000),
	TCP_DATA_OFFSET = __cpu_to_be32(0xF0000000)
}; 

static inline struct tcp_skb_cb *__tcp_skb_cb(struct sk_buff *skb)
{
	return ((struct tcp_skb_cb *)&((skb)->cb[0]));
}

#define TCP_SKB_CB(__skb) __tcp_skb_cb(__skb)

/* Due to TSO, an SKB can be composed of multiple actual
 * packets.  To keep these tracked properly, we use this.
 */
static inline int tcp_skb_pcount(const struct sk_buff *skb)
{
	return skb_shinfo(skb)->gso_segs;
}

/* This is valid iff tcp_skb_pcount() > 1. */
static inline int tcp_skb_mss(const struct sk_buff *skb)
{
	return skb_shinfo(skb)->gso_size;
}

/* Events passed to congestion control interface */
enum tcp_ca_event {
	CA_EVENT_TX_START,	/* first transmit when no packets in flight */
	CA_EVENT_CWND_RESTART,	/* congestion window restart */
	CA_EVENT_COMPLETE_CWR,	/* end of congestion recovery */
	CA_EVENT_FRTO,		/* fast recovery timeout */
	CA_EVENT_LOSS,		/* loss timeout */
	CA_EVENT_FAST_ACK,	/* in sequence ack */
	CA_EVENT_SLOW_ACK,	/* other ack */
};

/*
 * Interface for adding new TCP congestion control handlers
 */
#define TCP_CA_NAME_MAX	16
#define TCP_CA_MAX	128
#define TCP_CA_BUF_MAX	(TCP_CA_NAME_MAX*TCP_CA_MAX)

#define TCP_CONG_NON_RESTRICTED 0x1
#define TCP_CONG_RTT_STAMP	0x2

struct tcp_congestion_ops {
	struct list_head	list;
	unsigned long flags;

	/* initialize private data (optional) */
	void (*init)(struct sock *sk);
	/* cleanup private data  (optional) */
	void (*release)(struct sock *sk);

	/* return slow start threshold (required) */
	u32 (*ssthresh)(struct sock *sk);
	/* lower bound for congestion window (optional) */
	u32 (*min_cwnd)(const struct sock *sk);
	/* do new cwnd calculation (required) */
	void (*cong_avoid)(struct sock *sk, uint32_t ack, uint32_t in_flight);
	/* call before changing ca_state (optional) */
	void (*set_state)(struct sock *sk, uint8_t new_state);
	/* call when cwnd event occurs (optional) */
	void (*cwnd_event)(struct sock *sk, enum tcp_ca_event ev);
	/* new value of cwnd after loss (optional) */
	u32  (*undo_cwnd)(struct sock *sk);
	/* hook for packet ack accounting (optional) */
	void (*pkts_acked)(struct sock *sk, uint32_t num_acked, int32_t rtt_us);
	/* get info for inet_diag (optional) */
	void (*get_info)(struct sock *sk, uint32_t ext, struct sk_buff *skb);

	char 		name[TCP_CA_NAME_MAX];
	struct module 	*owner;
};

struct tcp_options_received {
/*	PAWS/RTTM data	*/
	long	ts_recent_stamp;/* Time we stored ts_recent (for aging) */
	u32	ts_recent;	/* Time stamp to echo next		*/
	u32	rcv_tsval;	/* Time stamp value             	*/
	u32	rcv_tsecr;	/* Time stamp echo reply        	*/
	u16 	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/
		tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/
		dsack : 1,	/* D-SACK is scheduled			*/
		wscale_ok : 1,	/* Wscale seen on SYN packet		*/
		sack_ok : 4,	/* SACK seen on SYN packet		*/
		snd_wscale : 4,	/* Window scaling received from sender	*/
		rcv_wscale : 4;	/* Window scaling to send to receiver	*/
	u8	cookie_plus:6,	/* bytes in authenticator/cookie option	*/
		cookie_out_never:1,
		cookie_in_always:1;
	u8	num_sacks;	/* Number of SACK blocks		*/
	u16	user_mss;	/* mss requested by user in ioctl	*/
	u16	mss_clamp;	/* Maximal mss, negotiated at connection setup */
};

#define TCP_CHECK_TIMER(sk) do { } while (0)

extern int sysctl_tcp_adv_win_scale;

#define TCPF_CA_Open	(1<<TCP_CA_Open)
#define TCPF_CA_Disorder (1<<TCP_CA_Disorder)
#define TCPF_CA_CWR	(1<<TCP_CA_CWR)
#define TCPF_CA_Recovery (1<<TCP_CA_Recovery)
#define TCPF_CA_Loss	(1<<TCP_CA_Loss)



/* - key database */
struct tcp_md5sig_key {
	u8			*key;
	u8			keylen;
};

/* Using SHA1 for now, define some constants.
 */
#define SHA_DIGEST_WORDS 5
#define SHA_MESSAGE_BYTES (512 /*bits*/ / 8)
#define COOKIE_DIGEST_WORDS (SHA_DIGEST_WORDS)
#define COOKIE_MESSAGE_WORDS (SHA_MESSAGE_BYTES / 4)
#define COOKIE_WORKSPACE_WORDS (COOKIE_DIGEST_WORDS + COOKIE_MESSAGE_WORDS)

/**
 *	struct tcp_extend_values - tcp_ipv?.c to tcp_output.c workspace.
 *
 *	As tcp_request_sock has already been extended in other places, the
 *	only remaining method is to pass stack values along as function
 *	parameters.  These parameters are not needed after sending SYNACK.
 *
 * @cookie_bakery:	cryptographic secret and message workspace.
 *
 * @cookie_plus:	bytes in authenticator/cookie option, copied from
 *			struct tcp_options_received (above).
 */
struct tcp_extend_values {
	struct request_values		rv;
	u32				cookie_bakery[COOKIE_WORKSPACE_WORDS];
	u8				cookie_plus:6,
					cookie_out_never:1,
					cookie_in_always:1;
};

#if !defined(OS_LINUX)


enum {
        TCP_ESTABLISHED = 1,
        TCP_SYN_SENT,
        TCP_SYN_RECV,
        TCP_FIN_WAIT1,
        TCP_FIN_WAIT2,
        TCP_TIME_WAIT,
        TCP_CLOSE,
        TCP_CLOSE_WAIT,
        TCP_LAST_ACK,
        TCP_LISTEN,
        TCP_CLOSING,/* Now a valid state */

        TCP_MAX_STATES/* Leave at the end! */
};

#define TCP_STATE_MASK0xF

#define TCP_ACTION_FIN (1 << 7)

enum tcp_ca_state {
        TCP_CA_Open = 0,
#define TCPF_CA_Open (1<<TCP_CA_Open)
        TCP_CA_Disorder = 1,
#define TCPF_CA_Disorder (1<<TCP_CA_Disorder)
        TCP_CA_CWR = 2,
#define TCPF_CA_CWR (1<<TCP_CA_CWR)
        TCP_CA_Recovery = 3,
#define TCPF_CA_Recovery (1<<TCP_CA_Recovery)
        TCP_CA_Loss = 4
#define TCPF_CA_Loss (1<<TCP_CA_Loss)
};

#define MSG_MORE MSG_HAVEMORE

#endif

#endif /* _SERVAL_TCP_USER_H_ */
