/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SCAFFOLD_UDP_SOCK_H
#define _SCAFFOLD_UDP_SOCK_H

#include <scaffold/netdevice.h>
#include <scaffold_sock.h>

/* The AF_SCAFFOLD socket */
struct scaffold_udp_sock {
	/* NOTE: scaffold_sock has to be the first member */
	struct scaffold_sock ssk;
        struct net_device *fake_dev; /* For testing only */
};

static inline struct scaffold_udp_sock *scaffold_udp_sk(const struct sock *sk)
{
	return (struct scaffold_udp_sock *)sk;
}

#endif /* _SCAFFOLD_UDP_SOCK_H */
