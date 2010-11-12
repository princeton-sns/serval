/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SKBUFF_H_
#define _SKBUFF_H_

#if defined(__KERNEL__)
#include <linux/skbuff.h>
#else
#include "sock.h"

struct sk_buff {
	struct sock		*sk;
	//struct net_device	*dev;
};

#endif /* __KERNEL__ */

#endif /* _SKBUFF_H_ */
