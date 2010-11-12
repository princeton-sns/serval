/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _NET_H_
#define _NET_H_

#if defined(__KERNEL__)
#include <linux/net.h>
#include <net/netns/hash.h>
#else

struct net {
	int foo;
};

static inline unsigned net_hash_mix(struct net *net)
{
	return 0;
}

#endif /* __KERNEL__ */

#endif /* _NET_H_ */
