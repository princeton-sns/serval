/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SOCK_H_
#define _SOCK_H_

#if defined(__KERNEL__)
#include <net/sock.h>
#else
#include <stdlib.h>
#include <scaffold/atomic.h>
#include <scaffold/lock.h>
#include "skbuff.h"
#include "net.h"

struct sock {
	int foo;
        atomic_t sk_refcount;
        spinlock_t sk_lock;
        struct net sk_net;
        void (*sk_destruct)(struct sock *sk);
	void (*sk_state_change)(struct sock *sk);
	void (*sk_data_ready)(struct sock *sk, int bytes);
	void (*sk_write_space)(struct sock *sk);
	/* void (*sk_error_report)(struct sock *sk); */
  	int (*sk_backlog_rcv)(struct sock *sk,
                              struct sk_buff *skb);  
};

#define sock_net(s) (&(s)->sk_net)

struct sock *sk_alloc(void);

static inline void sk_free(struct sock *sk)
{
        if (sk->sk_destruct)
                sk->sk_destruct(sk);
        free(sk);
}

static inline void sock_hold(struct sock *sk)
{
        atomic_inc(&sk->sk_refcount);
}

static inline void sock_put(struct sock *sk)
{
        if (atomic_dec_and_test(&sk->sk_refcount))
                sk_free(sk);
}

static inline void lock_sock(struct sock *sk)
{
        spin_lock(&sk->sk_lock);
}

static inline void release_sock(struct sock *sk)
{
        spin_unlock(&sk->sk_lock);
}

#endif /* __KERNEL__ */

#endif /* _SOCK_H_ */
