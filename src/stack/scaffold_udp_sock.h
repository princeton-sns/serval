/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SCAFFOLD_UDP_SOCK_H
#define _SCAFFOLD_UDP_SOCK_H

#include <scaffold_sock.h>

/* The AF_SCAFFOLD socket */
struct scaffold_udp_sock {
	/* NOTE: scaffol_sk has to be the first member */
	struct scaffold_sock scaffold_sk;
};

static inline struct scaffold_udp_sock *scaffold_usk(const struct sock *sk)
{
	return (struct scaffold_udp_sock *)sk;
}

#endif /* _SCAFFOLD_UDP_SOCK_H */
