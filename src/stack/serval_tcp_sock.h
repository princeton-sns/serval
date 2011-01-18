/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SERVAL_TCP_SOCK_H
#define _SERVAL_TCP_SOCK_H

#include <serval_sock.h>
#include <serval/skbuff.h>

/* The AF_SERVAL socket */
struct serval_tcp_sock {
	/* NOTE: serval_sock has to be the first member */
	struct serval_sock ssk;
        struct sk_buff_head out_of_order_queue;
};

static inline struct serval_tcp_sock *serval_tcp_sk(const struct sock *sk)
{
	return (struct serval_tcp_sock *)sk;
}

#endif /* _SERVAL_TCP_SOCK_H */
