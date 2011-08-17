/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _PACKET_H_
#define _PACKET_H_

#include <serval/netdevice.h>
#include <serval/skbuff.h>

#define SKB_HEADROOM_RESERVE (20+14)

struct packet_ops {
	int (*init)(struct net_device *);
	void (*destroy)(struct net_device *);
	int (*xmit)(struct sk_buff *);
	int (*recv)(struct net_device *);
};

#endif /* _PACKET_H_ */
