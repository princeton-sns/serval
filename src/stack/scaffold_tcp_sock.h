/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SCAFFOLD_TCP_SOCK_H
#define _SCAFFOLD_TCP_SOCK_H

#include <scaffold_sock.h>
#include <scaffold/skbuff.h>

/* The AF_SCAFFOLD socket */
struct scaffold_tcp_sock {
	/* NOTE: scaffold_sock has to be the first member */
	struct scaffold_sock ssk;
        struct sk_buff_head out_of_order_queue;
};

static inline struct scaffold_tcp_sock *scaffold_tcp_sk(const struct sock *sk)
{
	return (struct scaffold_tcp_sock *)sk;
}

#endif /* _SCAFFOLD_TCP_SOCK_H */
