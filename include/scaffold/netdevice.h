/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _NETDEVICE_H_
#define _NETDEVICE_H_

#include <scaffold/platform.h>

#if defined(OS_LINUX_KERNEL)
#include <linux/netdevice.h>
#endif /* OS_LINUX_KERNEL */

#if defined(OS_USER)
#include <scaffold/platform.h>
#include <scaffold/atomic.h>
#include <scaffold/lock.h>
#include <scaffold/list.h>
#include <net/if.h>
#if defined(OS_ANDROID)
#define ETH_HLEN 14
#else
#include <net/ethernet.h>
#endif
#if defined(OS_BSD)

struct ethhdr {
        u_char  h_dest[ETHER_ADDR_LEN];
        u_char  h_source[ETHER_ADDR_LEN];
        u_short h_proto;
};

#endif

struct sk_buff;

#ifdef MAX_ADDR_LEN
#undef MAX_ADDR_LEN /* also defined in if_arp.h */
#endif

#define MAX_ADDR_LEN ETH_HLEN
#define LL_MAX_HEADER 32
#define MAX_HEADER LL_MAX_HEADER

struct net_device {        
	int                     ifindex;
        char                    name[IFNAMSIZ];
	unsigned short		hard_header_len;	/* hardware hdr length	*/
	unsigned char		*dev_addr;
	unsigned char		perm_addr[MAX_ADDR_LEN]; /* permanent hw address */
	unsigned char		addr_len;	/* hardware address length	*/
	unsigned char		broadcast[MAX_ADDR_LEN];	/* hw bcast add	*/
	spinlock_t              lock;
	atomic_t		refcnt;
	struct list_head	dev_list;
};

#define LL_RESERVED_SPACE(dev) ((dev)->hard_header_len)
#define LL_RESERVED_SPACE_EXTRA(dev,extra) ((dev)->hard_header_len + (extra))
#define LL_ALLOCATED_SPACE(dev) ((dev)->hard_header_len)

#include <scaffold/skbuff.h>

static inline int dev_hard_header(struct sk_buff *skb, struct net_device *dev,
				  unsigned short type,
				  const void *daddr, const void *saddr,
				  unsigned len)
{
	struct ethhdr *ethh = (struct ethhdr *)skb_push(skb, ETH_HLEN);

	ethh->h_proto = htons(type);

	if (!dev) {
		if (!skb->dev)
			return -ETH_HLEN;
		dev = skb->dev;
	}

	if (!saddr)
		saddr = dev->dev_addr;
       
	memcpy(ethh->h_source, saddr, ETH_ALEN);

        if (daddr) {
                memcpy(ethh->h_dest, daddr, ETH_ALEN);
                return ETH_HLEN;
        }

	return -ETH_HLEN;
}

void ether_setup(struct net_device *dev);
struct net_device *alloc_netdev(int sizeof_priv, const char *name,
				void (*setup)(struct net_device *));
void free_netdev(struct net_device *dev);

static inline void dev_put(struct net_device *dev)
{
	free_netdev(dev);
}

static inline void dev_hold(struct net_device *dev)
{
	atomic_inc(&dev->refcnt);
}

#endif /* OS_USER */

#endif /* _NETDEVICE_H_ */
