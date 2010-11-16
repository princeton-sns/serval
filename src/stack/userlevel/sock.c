/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/debug.h>
#include <scaffold/lock.h>
#include <pthread.h>
#include "timer.h"
#include "sock.h"
#include "wait.h"

struct net init_net;

#define RCV_BUF_DEFAULT 1000
#define SND_BUF_DEFAULT 1000

LIST_HEAD(proto_list);
DEFINE_RWLOCK(proto_list_lock);

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

void sock_init_data(struct socket *sock, struct sock *sk)
{
	skb_queue_head_init(&sk->sk_receive_queue);
	skb_queue_head_init(&sk->sk_write_queue);

	sk->sk_send_head	=	NULL;
	init_timer(&sk->sk_timer);
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
        init_waitqueue_head(sk_sleep(sk));
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

static void sk_destroy(struct sock *sk)
{
        sk->sk_destruct(sk);
        destroy_waitqueue_head(sk_sleep(sk));
}

int proto_register(struct proto *prot, int ignore)
{
	write_lock(&proto_list_lock);
	list_add(&prot->node, &proto_list);
	/* assign_proto_idx(prot); */
	write_unlock(&proto_list_lock);

	return 0;
}

void proto_unregister(struct proto *prot)
{
        write_lock(&proto_list_lock);
	/* release_proto_idx(prot); */
	list_del(&prot->node);
	write_unlock(&proto_list_lock);
}


int sk_wait_data(struct sock *sk, long *timeo)
{
        return 0;
}



void sk_reset_timer(struct sock *sk, struct timer_list* timer,
                    unsigned long expires)
{
}

void sk_stop_timer(struct sock *sk, struct timer_list* timer)
{
}

int sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
        return 0;
}

int sock_queue_err_skb(struct sock *sk, struct sk_buff *skb)
{
        return 0;
}
