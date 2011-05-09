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
#include <serval_srv.h>
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

atomic_t serval_tcp_memory_allocated;	/* Current allocated memory. */

/*
 * Pressure flag: try to collapse.
 * Technical note: it is used by multiple contexts non atomically.
 * All the __sk_mem_schedule() is of this nature: accounting
 * is strict, actions are advisory and have some latency.
 */
int serval_tcp_memory_pressure;

static int serval_tcp_disconnect(struct sock *sk, int flags)
{
        return 0;
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
                                           struct tcp_options_received *rx_opt,
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
	struct tcp_options_received tmp_opt;
        
        if (!pskb_may_pull(skb, sizeof(struct tcphdr))) {
                LOG_ERR("No TCP header?\n");
                FREE_SKB(skb);
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
	tmp_opt.mss_clamp = TCP_MSS_DEFAULT;
	tmp_opt.user_mss  = tp->rx_opt.user_mss;
	//tcp_parse_options(skb, &tmp_opt, &hash_location, 0);

        serval_tcp_openreq_init(req, &tmp_opt, skb);

        trsk->snt_isn = serval_tcp_init_sequence(skb);

        return 0;
}

static void serval_tcp_connection_respond_sock(struct sock *sk, 
                                               struct sk_buff *skb,
                                               struct request_sock *rsk,
                                               struct sock *child,
                                               struct dst_entry *dst);

/* 
   Receive from network
*/
static int serval_tcp_rcv(struct sock *sk, struct sk_buff *skb)
{
        struct tcphdr *tcph = tcp_hdr(skb);
        int err = 0;
        
        LOG_DBG("TCP packet seq=%lu ack=%lu\n",  
                ntohl(tcph->seq),
                ntohl(tcph->ack_seq));

        FREE_SKB(skb);

        return err;
}

static unsigned int serval_tcp_xmit_size_goal(struct sock *sk, u32 mss_now,
                                              int large_allowed)
{
        return 40;
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

/* From net/ipv4/tcp.c */
struct sk_buff *sk_stream_alloc_skb(struct sock *sk, int size, gfp_t gfp)
{
	struct sk_buff *skb;

	/* The TCP header must be at least 32-bit aligned.  */
	size = ALIGN(size, 4);

	skb = alloc_skb(size + sk->sk_prot->max_header, gfp);

	if (skb) {
		if (sk_wmem_schedule(sk, skb->truesize)) {
			/*
			 * Make sure that we have exactly size bytes
			 * available to the caller, no more, no less.
			 */
			skb_reserve(skb, skb_tailroom(skb) - size);
			return skb;
		}
		__kfree_skb(skb);
	} else {
		sk->sk_prot->enter_memory_pressure(sk);
                /* FIXME */
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
		if (sk_can_gso(sk))
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
				if (sk->sk_route_caps & NETIF_F_ALL_CSUM)
					skb->ip_summed = CHECKSUM_PARTIAL;

				skb_entail(sk, skb);
				copy = size_goal;
				max = size_goal;
			}

			/* Try to append data to the end of skb. */
			if (copy > seglen)
				copy = seglen;

			/* Where to copy to? */
			if (skb_tailroom(skb) > 0) {
                                LOG_DBG("Add data\n");
				/* We have some space in skb head. Superb! */
				if (copy > skb_tailroom(skb))
					copy = skb_tailroom(skb);
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

                        LOG_DBG("mss_now=%d\n", mss_now);
		}
	}

out:
	if (copied)
		serval_tcp_push(sk, flags, mss_now, tp->nonagle);
	TCP_CHECK_TIMER(sk);
	release_sock(sk);
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

#if 0
	if (inet_csk_ack_scheduled(sk)) {
		const struct inet_connection_sock *icsk = inet_csk(sk);
		   /* Delayed ACKs frequently hit locked sockets during bulk
		    * receive. */
		if (icsk->icsk_ack.blocked ||
		    /* Once-per-two-segments ACK was not sent by tcp_input.c */
		    tp->rcv_nxt - tp->rcv_wup > icsk->icsk_ack.rcv_mss ||
		    /*
		     * If this read emptied read buffer, we send ACK, if
		     * connection is not bidirectional, user drained
		     * receive buffer and there was a small segment
		     * in queue.
		     */
		    (copied > 0 &&
		     ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED2) ||
		      ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED) &&
		       !icsk->icsk_ack.pingpong)) &&
		      !atomic_read(&sk->sk_rmem_alloc)))
			time_to_ack = 1;
	}
#endif
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
        /*
	if (time_to_ack)
		serval_tcp_send_ack(sk);
        */
}

static void tcp_prequeue_process(struct sock *sk)
{
	struct sk_buff *skb;
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	//NET_INC_STATS_USER(sock_net(sk), LINUX_MIB_TCPPREQUEUED);

	/* RX process wants to run with disabled BHs, though it is not
	 * necessary */
	local_bh_disable();
	while ((skb = __skb_dequeue(&tp->ucopy.prequeue)) != NULL)
		sk_backlog_rcv(sk, skb);
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
				tcp_prequeue_process(sk);

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

			tcp_prequeue_process(sk);

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

static struct serval_sock_af_ops serval_tcp_af_ops = {
        .queue_xmit = serval_ipv4_xmit_skb,
        .receive = serval_tcp_rcv,
        .conn_build_syn = serval_tcp_connection_build_syn,
        .conn_build_synack = serval_tcp_connection_build_synack,
        .conn_build_ack = serval_tcp_connection_build_ack,
        .conn_request = serval_tcp_connection_request,
        .request_state_process = serval_tcp_syn_sent_state_process,
        .respond_state_process = serval_tcp_syn_recv_state_process,
        .conn_child_sock = serval_tcp_connection_respond_sock,
};

/**
   Called when a child sock is created in response to a successful
   three-way handshake on the server side.
 */
void serval_tcp_connection_respond_sock(struct sock *sk, 
                                        struct sk_buff *skb,
                                        struct request_sock *rsk,
                                        struct sock *newsk,
                                        struct dst_entry *dst)
{
        //struct serval_sock *new_ssk = serval_sk(newsk);
        //struct inet_sock *newinet = inet_sk(newsk);
        struct inet_request_sock *ireq = inet_rsk(rsk);
        struct serval_tcp_sock *newtp = serval_tcp_sk(newsk);
        struct serval_tcp_sock *oldtp = serval_tcp_sk(sk);
        struct serval_tcp_request_sock *treq = serval_tcp_rsk(rsk);

        LOG_DBG("Initializing new TCP respond sock\n");

	newtp->pred_flags = 0;

        newtp->rcv_wup = newtp->copied_seq =
		newtp->rcv_nxt = treq->rcv_isn + 1;

        newtp->snd_sml = newtp->snd_una =
		newtp->snd_nxt = newtp->snd_up =
                treq->snt_isn + 1 + serval_tcp_s_data_size(oldtp);

        serval_tcp_prequeue_init(newtp);

        serval_tcp_init_wl(newtp, treq->rcv_isn);

        newtp->srtt = 0;
        newtp->mdev = TCP_TIMEOUT_INIT;
        newtp->rto = TCP_TIMEOUT_INIT;

        newtp->packets_out = 0;
        newtp->retrans_out = 0;
        newtp->sacked_out = 0;
        newtp->fackets_out = 0;
        newtp->snd_ssthresh = TCP_INFINITE_SSTHRESH;

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
        //tcp_init_xmit_timers(newsk);
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
        newtp->window_clamp = treq->window_clamp;
        newtp->rcv_ssthresh = treq->rcv_wnd;
        newtp->rcv_wnd = treq->rcv_wnd;
        newtp->rx_opt.wscale_ok = treq->wscale_ok;

        if (newtp->rx_opt.wscale_ok) {
                newtp->rx_opt.snd_wscale = ireq->snd_wscale;
                newtp->rx_opt.rcv_wscale = ireq->rcv_wscale;
        } else {
                newtp->rx_opt.snd_wscale = newtp->rx_opt.rcv_wscale = 0;
                newtp->window_clamp = min(newtp->window_clamp, 65535U);
        }
        newtp->snd_wnd = (ntohs(tcp_hdr(skb)->window) <<
                          newtp->rx_opt.snd_wscale);
        newtp->max_window = newtp->snd_wnd;

                
        if (0 /*newtp->rx_opt.tstamp_ok */) {
                /*
                  newtp->rx_opt.ts_recent = req->ts_recent;
                  newtp->rx_opt.ts_recent_stamp = get_seconds();
                  newtp->tcp_header_len = sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED;
                */
        } else {
                newtp->rx_opt.ts_recent_stamp = 0;
                newtp->tcp_header_len = sizeof(struct tcphdr);
        }
/*
  if (skb->len >= TCP_MSS_DEFAULT + newtp->tcp_header_len)
  newicsk->icsk_ack.last_seg_size = skb->len - newtp->tcp_header_len;
*/
        newtp->rx_opt.mss_clamp = treq->mss;

////

	//newsk->sk_gso_type = SKB_GSO_TCPV4;
	sk_setup_caps(newsk, dst);
	
	//newinet->inet_id = newtp->write_seq ^ jiffies;

	serval_tcp_mtup_init(newsk);
#if defined(OS_LINUX_KERNEL)
        serval_tcp_sync_mss(newsk, dst_mtu(dst));
	newtp->advmss = dst_metric(dst, RTAX_ADVMSS);
#else
        serval_tcp_sync_mss(newsk, TCP_MSS_DEFAULT);
	newtp->advmss = TCP_MSS_DEFAULT;
#endif

	if (serval_tcp_sk(sk)->rx_opt.user_mss &&
	    serval_tcp_sk(sk)->rx_opt.user_mss < newtp->advmss)
		newtp->advmss = serval_tcp_sk(sk)->rx_opt.user_mss;

	serval_tcp_initialize_rcv_mss(newsk);
}

static int serval_tcp_init_sock(struct sock *sk)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_tcp_sock *tp = serval_tcp_sk(sk);

        LOG_DBG("Initializing new TCP sock\n");

        skb_queue_head_init(&tp->out_of_order_queue);
	serval_tcp_prequeue_init(tp);

        tp->rto = TCP_TIMEOUT_INIT;
	tp->mdev = TCP_TIMEOUT_INIT;
        	/* So many TCP implementations out there (incorrectly) count the
	 * initial SYN frame in their delayed-ACK and congestion control
	 * algorithms that we must have the following bandaid to talk
	 * efficiently to them.  -DaveM
	 */
	tp->snd_cwnd = 2;

	/* See draft-stevens-tcpca-spec-01 for discussion of the
	 * initialization of these values.
	 */
	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
	tp->snd_cwnd_clamp = ~0;
	tp->mss_cache = TCP_MSS_DEFAULT;

	tp->reordering = sysctl_tcp_reordering;

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
        struct serval_tcp_sock *tsk = serval_tcp_sk(sk);
   
        LOG_DBG("destroying TCP sock\n");

	/* Cleanup up the write buffer. */
	serval_tcp_write_queue_purge(sk);

	__skb_queue_purge(&tsk->out_of_order_queue);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
        return 0;
#endif
}

static void serval_tcp_request_sock_destructor(struct request_sock *rsk)
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
	.close  		= serval_srv_close,   
        .connect                = serval_srv_connect,
	.disconnect		= serval_tcp_disconnect,
	.shutdown		= serval_tcp_shutdown,
        .sendmsg                = serval_tcp_sendmsg,
        .recvmsg                = serval_tcp_recvmsg,
	.backlog_rcv		= serval_srv_do_rcv,
        .hash                   = serval_sock_hash,
        .unhash                 = serval_sock_unhash,
#if defined(OS_LINUX_KERNEL)
	/* .enter_memory_pressure	= tcp_enter_memory_pressure, */
	.sockets_allocated	= &tcp_sockets_allocated,
	.orphan_count		= &tcp_orphan_count,
	.memory_allocated	= &serval_tcp_memory_allocated,
	.memory_pressure	= &serval_tcp_memory_pressure,
	.sysctl_mem		= sysctl_tcp_mem,
	.sysctl_wmem		= sysctl_tcp_wmem,
	.sysctl_rmem		= sysctl_tcp_rmem,
#endif
	.max_header		= MAX_SERVAL_TCP_HEADER,
	.obj_size		= sizeof(struct serval_tcp_sock),
	.rsk_prot		= &tcp_request_sock_ops,
};
