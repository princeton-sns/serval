/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/debug.h>
#include <scaffold/lock.h>
#include "sock.h"

static struct net init_net;

#define RCV_BUF_DEFAULT 1000
#define SND_BUF_DEFAULT 1000

#define MAX_SCHEDULE_TIMEOUT 1000

static void sock_def_destruct(struct sock *sk)
{

}

static void sock_def_wakeup(struct sock *sk)
{

}

static void sock_def_readable(struct sock *sk, int bytes)
{

}

static void sock_def_write_space(struct sock *sk)
{

}

static int sock_def_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

static inline void sock_lock_init(struct sock *sk)
{
	spin_lock_init(&(sk)->sk_lock);
}

void sock_init_data(/*struct socket *sock, */ struct sock *sk)
{
	skb_queue_head_init(&sk->sk_receive_queue);
	skb_queue_head_init(&sk->sk_write_queue);

	sk->sk_send_head	=	NULL;
/*
	init_timer(&sk->sk_timer);
*/
	sk->sk_net              =       &init_net;
	sk->sk_rcvbuf		=	RCV_BUF_DEFAULT;
	sk->sk_sndbuf		=       SND_BUF_DEFAULT;
	sk->sk_state		=	0;
	sock_set_flag(sk, SOCK_ZAPPED);
	sk->sk_state_change	=	sock_def_wakeup;
	sk->sk_data_ready	=	sock_def_readable;
	sk->sk_write_space	=	sock_def_write_space;
	sk->sk_destruct		=	sock_def_destruct;
	sk->sk_backlog_rcv	=	sock_def_backlog_rcv;
	sk->sk_write_pending	=	0;
	sk->sk_rcvtimeo		=	MAX_SCHEDULE_TIMEOUT;
	sk->sk_sndtimeo		=	MAX_SCHEDULE_TIMEOUT;

	atomic_set(&sk->sk_refcnt, 1);
	atomic_set(&sk->sk_drops, 0);
}

static struct sock *sk_prot_alloc(struct proto *prot, int family)
{
	struct sock *sk;

	sk = (struct sock *)malloc(prot->obj_size);

	if (sk) {

	}

	return sk;
}

#define get_net(n) n

static void sock_net_set(struct sock *sk, struct net *net)
{
	/* TODO: make sure this is ok. Should be since we have no
	   network namespaces anyway. */
	sk->sk_net = net;
}

struct sock *sk_alloc(struct net *net, int family, gfp_t priority,
		      struct proto *prot)
{
	struct sock *sk = NULL;

	sk = sk_prot_alloc(prot, family);

	if (sk) {
		sk->sk_family = family;
		/*
		 * See comment in struct sock definition to understand
		 * why we need sk_prot_creator -acme
		 */
		sk->sk_prot = prot;
		sock_lock_init(sk);
		sock_net_set(sk, get_net(net));
		atomic_set(&sk->sk_wmem_alloc, 1);
	}

	return sk;
}

int proto_register(struct proto *prot, int *ignore)
{

	return 0;
}

void proto_unregister(struct proto *prot)
{
}
