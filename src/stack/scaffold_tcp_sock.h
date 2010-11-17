/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SCAFFOLD_TCP_SOCK_H
#define _SCAFFOLD_TCP_SOCK_H

#include <scaffold_sock.h>

/* The AF_SCAFFOLD socket */
struct scaffold_tcp_sock {
	/* NOTE: scaffold_sock has to be the first member */
	struct scaffold_sock ssk;
};

static inline struct scaffold_tcp_sock *scaffold_tsk(const struct sock *sk)
{
	return (struct scaffold_tcp_sock *)sk;
}

#endif /* _SCAFFOLD_TCP_SOCK_H */
