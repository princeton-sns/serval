/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/platform.h>
#include <serval/debug.h>
#include <serval/netdevice.h>
#include <serval/skbuff.h>
#include <serval/sock.h>
#include <serval/bitops.h>
#include <netinet/serval.h>
#include <serval_tcp_sock.h>
#include <serval_srv.h>
#include <input.h>

#if defined(OS_LINUX_KERNEL)
#include <linux/ip.h>
#define ENABLE_PAGE 1
#endif

#if defined(OS_USER)
#include <netinet/ip.h>
#if defined(OS_BSD)
#include <serval/platform_tcpip.h>
#else
#include <netinet/tcp.h>
#endif
#endif /* OS_USER */
#include <serval_tcp.h>

int sysctl_tcp_moderate_rcvbuf = 1;

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

		if (sysctl_tcp_moderate_rcvbuf &&
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
