/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SERVAL_SAL_H_
#define _SERVAL_SAL_H_

#include <serval/skbuff.h>
#include <serval/sock.h>
#include <netinet/serval.h>
#include <serval_sock.h>
#include <serval/debug.h>

int serval_sal_xmit_skb(struct sk_buff *skb);

struct service_entry;

/* 
   NOTE:
   
   We must be careful that this struct does not overflow the 48 bytes
   that the skb struct gives us in the cb field.
   
   Transport protocols (i.e., in most cases TCP) reserve some room for
   lower layer control blocks (e.g., IPv4/IPv6) at the head of their
   own control block. This is done in order to keep the lower layer
   information when processing incoming packets. We should therefore
   be careful not to overwrite the IP control block in incoming
   packets in case TCP expects it to be there.

   For outgoing packets, we are free to overwrite the control block
   with our own information. Any packets queued by the transport
   protocol are cloned before transmission, so the original
   information will be preserved in the queued packet.

   We should be careful to do the same in the SAL layer when queuing
   packets; i.e., we should always clone queued packets before we
   transmit.
 */
 struct sal_skb_cb {
         u8 flags;
         u32 verno;
         u32 when;
         struct service_id *srvid;
 };

enum sal_ctrl_flags {
        SVH_SYN       = 1 << 0,
        SVH_RSYN      = 1 << 1,
        SVH_ACK       = 1 << 2,
        SVH_NACK      = 1 << 3,
        SVH_RST       = 1 << 4,
        SVH_FIN       = 1 << 5,
        SVH_CONN_ACK  = 1 << 6, /* Only used internally to signal that
                                   the ACK should carry a connection
                                   extension (for SYN-ACKs). */
        SVH_RETRANS   = 1 << 7,
};

#define sal_time_stamp ((u32)(jiffies))

static inline struct sal_skb_cb *__sal_skb_cb(struct sk_buff *skb)
{
        struct sal_skb_cb * sscb = 
                (struct sal_skb_cb *)&(skb)->cb[0];
#if defined(ENABLE_DEBUG)
        /*
          if (sizeof(struct sal_skb_cb) > sizeof(skb->cb)) {
                 LOG_WARN("sal_skb_cb (%zu bytes) > skb->cb (%zu bytes). "
                          "skb->cb may overflow!\n", 
                          sizeof(struct sal_skb_cb), 
                          sizeof(skb->cb));
         } 
         */
         /*
            else {
                LOG_WARN("sal_skb_cb (%zu bytes) skb->cb (%zu bytes).\n", 
                         sizeof(struct sal_skb_cb), 
                         sizeof(skb->cb));
                 } 
          */
#endif
	return sscb;
}

#define SAL_SKB_CB(__skb) __sal_skb_cb(__skb)

extern int sysctl_tcp_fin_timeout;
extern int sysctl_sal_keepalive_time;
extern int sysctl_sal_keepalive_probes;
extern int sysctl_sal_keepalive_intvl;

#define MAX_CTRL_QUEUE_LEN 20

/* control queue abstraction */
static inline void serval_sal_ctrl_queue_purge(struct sock *sk)
{
	struct sk_buff *skb;

	while ((skb = __skb_dequeue(&serval_sk(sk)->ctrl_queue)) != NULL) {
		FREE_SKB(skb);
	}
	/* serval_sal_clear_all_retrans_hints(serval_sal_sk(sk)); */
}

static inline struct sk_buff *serval_sal_ctrl_queue_head(struct sock *sk)
{
	return skb_peek(&serval_sk(sk)->ctrl_queue);
}

static inline struct sk_buff *serval_sal_ctrl_queue_tail(struct sock *sk)
{
	return skb_peek_tail(&serval_sk(sk)->ctrl_queue);
}

static inline struct sk_buff *serval_sal_ctrl_queue_next(struct sock *sk, 
							 struct sk_buff *skb)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28))
	return skb_queue_next(&serval_sk(sk)->ctrl_queue, skb);
#else
        return skb->next;
#endif
}

static inline struct sk_buff *serval_sal_ctrl_queue_prev(struct sock *sk, 
							 struct sk_buff *skb)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29))
	return skb_queue_prev(&serval_sk(sk)->ctrl_queue, skb);
#else
        return skb->prev;
#endif
}

#define serval_sal_for_ctrl_queue(skb, sk)	\
	skb_queue_walk(&(sk)->ctrl_queue, skb)

#define serval_sal_for_ctrl_queue_from(skb, sk)		\
	skb_queue_walk_from(&(sk)->ctrl_queue, skb)

#define serval_sal_for_ctrl_queue_from_safe(skb, tmp, sk)	\
	skb_queue_walk_from_safe(&(sk)->ctrl_queue, skb, tmp)

static inline struct sk_buff *serval_sal_send_head(struct sock *sk)
{
	return serval_sk(sk)->ctrl_send_head;
}

static inline int serval_sal_skb_is_last(const struct sock *sk,
					 const struct sk_buff *skb)
{

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28))
	return skb_queue_is_last(&serval_sk(sk)->ctrl_queue, skb);
#else
        return (skb->next == (struct sk_buff *)&serval_sk(sk)->ctrl_queue);
#endif
}

static inline void serval_sal_advance_send_head(struct sock *sk, 
						struct sk_buff *skb)
{
	if (serval_sal_skb_is_last(sk, skb))
		serval_sk(sk)->ctrl_send_head = NULL;
	else
		serval_sk(sk)->ctrl_send_head = 
			serval_sal_ctrl_queue_next(sk, skb);
}

static inline void serval_sal_check_send_head(struct sock *sk, 
					      struct sk_buff *skb_unlinked)
{
	if (serval_sk(sk)->ctrl_send_head == skb_unlinked)
		serval_sk(sk)->ctrl_send_head = NULL;
}

static inline void serval_sal_init_send_head(struct sock *sk)
{
	serval_sk(sk)->ctrl_send_head = NULL;
}

static inline void serval_sal_init_ctrl_queue(struct sock *sk)
{
        skb_queue_head_init(&serval_sk(sk)->ctrl_queue);
        serval_sal_init_send_head(sk);
}

static inline void __serval_sal_add_ctrl_queue_tail(struct sock *sk, 
						    struct sk_buff *skb)
{
	__skb_queue_tail(&serval_sk(sk)->ctrl_queue, skb);
}

static inline void serval_sal_add_ctrl_queue_tail(struct sock *sk, 
						  struct sk_buff *skb)
{
	__serval_sal_add_ctrl_queue_tail(sk, skb);

	/* Queue it, remembering where we must start sending. */
	if (serval_sk(sk)->ctrl_send_head == NULL) {
		serval_sk(sk)->ctrl_send_head = skb;
	}
}

static inline void __serval_sal_add_ctrl_queue_head(struct sock *sk, 
						    struct sk_buff *skb)
{
	__skb_queue_head(&serval_sk(sk)->ctrl_queue, skb);
}

/* Insert buff after skb on the control queue of serval sk.  */
static inline void serval_sal_insert_ctrl_queue_after(struct sk_buff *skb,
						      struct sk_buff *buff,
						      struct sock *sk)
{
	__skb_queue_after(&serval_sk(sk)->ctrl_queue, skb, buff);
}

/* Insert new before skb on the control queue of serval_sk.  */
static inline void serval_sal_insert_ctrl_queue_before(struct sk_buff *new,
						       struct sk_buff *skb,
						       struct sock *sk)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26))
	__skb_queue_before(&serval_sk(sk)->ctrl_queue, skb, new);
#else
        __skb_insert(new, skb->prev, skb, &serval_sk(sk)->ctrl_queue);
#endif
	if (serval_sk(sk)->ctrl_send_head == skb)
		serval_sk(sk)->ctrl_send_head = new;
}

static inline void serval_sal_unlink_ctrl_queue(struct sk_buff *skb, 
						struct sock *sk)
{
	__skb_unlink(skb, &serval_sk(sk)->ctrl_queue);
}

static inline int serval_sal_ctrl_queue_empty(struct sock *sk)
{
	return skb_queue_empty(&serval_sk(sk)->ctrl_queue);
}

static inline unsigned int serval_sal_ctrl_queue_len(struct sock *sk)
{
        return skb_queue_len(&serval_sk(sk)->ctrl_queue);
}

int serval_sal_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);
void serval_sal_close(struct sock *sk, long timeout);
int serval_sal_migrate(struct sock *sk);
int serval_sal_do_rcv(struct sock *sk, struct sk_buff *skb);
void serval_sal_rexmit_timeout(unsigned long data);
void serval_sal_timewait_timeout(unsigned long data);
int serval_sal_send_shutdown(struct sock *sk);
int serval_sal_recv_shutdown(struct sock *sk);
void serval_sal_done(struct sock *sk);
int serval_sal_rcv(struct sk_buff *skb);
int serval_sal_reresolve(struct sk_buff *skb);

void serval_sal_keepalive_timeout(unsigned long data);

static inline int serval_sal_keepalive_intvl_when(const struct serval_sock *ssk)
{
	return ssk->keepalive_intvl ? : sysctl_sal_keepalive_intvl;
}

static inline int serval_sal_keepalive_time_when(const struct serval_sock *ssk)
{
	return ssk->keepalive_time ? : sysctl_sal_keepalive_time;
}

static inline int serval_sal_keepalive_probes(const struct serval_sock *ssk)
{
	return ssk->keepalive_probes ? : sysctl_sal_keepalive_probes;
}

static inline u32 serval_sal_keepalive_time_elapsed(const struct serval_sock *ssk)
{
	return min_t(u32, sal_time_stamp - ssk->last_rcv_tstamp,
			  sal_time_stamp - ssk->ack_rcv_tstamp);
}

void serval_sal_rcv_reset(struct sock *sk);
void serval_sal_send_active_reset(struct sock *sk, gfp_t priority);

static inline struct sal_hdr *sal_hdr(struct sk_buff *skb)
{
        return (struct sal_hdr *)skb_transport_header(skb);
}

int serval_sal_send_fin(struct sock *sk);
void serval_sal_update_rtt(struct sock *sk, const s32 seq_rtt);

#define EXTRA_HDR_SIZE (20)
#define IP_HDR_SIZE sizeof(struct iphdr)
/* payload + LL + IP + extra */
#define MAX_SAL_HDR (MAX_HEADER + IP_HDR_SIZE + EXTRA_HDR_SIZE + \
                     sizeof(struct sal_hdr) +                    \
                     sizeof(struct sal_control_ext) +            \
                     2 * sizeof(struct sal_service_ext))

#define SAL_NET_HEADER_LEN (sizeof(struct iphdr) +              \
                            sizeof(struct sal_hdr))

extern int serval_sal_forwarding;


#define SAL_RTO_MAX	((unsigned)(120*HZ))
#define SAL_RTO_MIN	((unsigned)(HZ/5))
#define SAL_TIMEOUT_INIT ((unsigned)(3*HZ))
#define SAL_RETRANSMITS_MAX 15

#define SAL_RESOURCE_PROBE_INTERVAL ((unsigned)(HZ/2U)) /* Maximal interval between probes
					                 * for local resources.
					                 */
#define SAL_TIMEWAIT_LEN (60*HZ) /* how long to wait to destroy TIME-WAIT
				  * state, about 60 seconds	*/
#define SAL_FIN_TIMEOUT	SAL_TIMEWAIT_LEN
                                 /* BSD style FIN_WAIT2 deadlock breaker.
				  * It used to be 3min, new value is 60sec,
				  * to combine FIN-WAIT-2 timeout with
				  * TIME-WAIT timer.
				  */

#define SAL_KEEPALIVE_TIME	(120*60*HZ) /* two hours */
#define SAL_KEEPALIVE_PROBES	9	    /* Max of 9 keepalive probes */
#define SAL_KEEPALIVE_INTVL	(75*HZ)

#endif /* _SERVAL_SAL_H_ */
