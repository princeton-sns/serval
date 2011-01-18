/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _NETDEVICE_H_
#define _NETDEVICE_H_

#include <serval/platform.h>

#if defined(OS_LINUX_KERNEL)
#include <linux/netdevice.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
static inline void skb_set_dev(struct sk_buff *skb, struct net_device *dev)
{
	skb->dev = dev;
}
#endif

#include <linux/inetdevice.h>

static inline int dev_get_ipv4_addr(struct net_device *dev, void *addr)
{
        struct in_device *indev = in_dev_get(dev);
        int ret = 0;

        for_primary_ifa(indev) {
                memcpy(addr, &ifa->ifa_address, 4);
                ret = 1;
                break;
        }
        endfor_ifa(indev);

        in_dev_put(indev);
        return ret;
}

static inline int dev_get_ipv4_broadcast(struct net_device *dev, void *addr)
{
        struct in_device *indev = in_dev_get(dev);
        int ret = 0;

        for_primary_ifa(indev) {
                memcpy(addr, &ifa->ifa_broadcast, 4);
                ret = 1;
                break;
        }
        endfor_ifa(indev);

        in_dev_put(indev);
        return 0;
}

static inline int dev_get_ipv4_netmask(struct net_device *dev, void *addr)
{
        struct in_device *indev = in_dev_get(dev);
        int ret = 0;

        for_primary_ifa(indev) {
                memcpy(addr, &ifa->ifa_mask, 4);
                ret = 1;
                break;
        }
        endfor_ifa(indev);

        in_dev_put(indev);
        return 0;
}

#endif /* OS_LINUX_KERNEL */

#if defined(OS_USER)
#include <serval/platform.h>
#include <serval/atomic.h>
#include <serval/lock.h>
#include <serval/net.h>
#include <serval/skbuff.h>
#include <net/if.h>
#include <pthread.h>
#include <string.h>
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
struct packet_ops;


#ifndef MAX_ADDR_LEN
#define MAX_ADDR_LEN ETH_HLEN
#endif
#define LL_MAX_HEADER 32
#define MAX_HEADER LL_MAX_HEADER

#define NET_XMIT_SUCCESS	0x00
#define NET_XMIT_DROP		0x01	/* skb dropped			*/
#define NET_XMIT_CN		0x02	/* congestion notification	*/
#define NET_XMIT_POLICED	0x03	/* skb is shot by police	*/
#define NET_XMIT_MASK		0x0f	/* qdisc flags in net/sch_generic.h */

struct netdev_queue {
	struct net_device	*dev;
	struct sk_buff_head	q;
};

struct net_device {        
	int                     ifindex;
        char                    name[IFNAMSIZ];
	unsigned short		hard_header_len; /* hardware hdr length	*/
	unsigned char		*dev_addr;
	unsigned char		perm_addr[MAX_ADDR_LEN]; /* permanent hw address */
	unsigned char		addr_len;  /* hardware address length	*/
	unsigned char		broadcast[MAX_ADDR_LEN]; /* hw bcast add	*/
	unsigned int		flags;	/* interface flags (a la BSD)	*/
	spinlock_t              lock;
	atomic_t		refcnt;
	/* device name hash chain */
	struct hlist_node	name_hlist;
	/* device index hash chain */
	struct hlist_node	index_hlist;
	struct list_head	dev_list;
        struct netdev_queue     tx_queue;
        unsigned long           tx_queue_len; /* Max len allowed */
        struct {
                uint32_t addr;
                uint32_t broadcast;
                uint32_t netmask;
        } ipv4;
        /* Stuff for packet thread that reads packets from the
         * device */
        int fd;
        int pipefd[2];
        int should_exit;
        pthread_t thr;
        struct packet_ops *pack_ops;
        /* Here follows private data */
};

#define LL_RESERVED_SPACE(dev) ((dev)->hard_header_len)
#define LL_RESERVED_SPACE_EXTRA(dev,extra) ((dev)->hard_header_len + (extra))
#define LL_ALLOCATED_SPACE(dev) ((dev)->hard_header_len)

#include <serval/skbuff.h>

static inline void skb_set_dev(struct sk_buff *skb, struct net_device *dev)
{
	skb->dev = dev;
}

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
int register_netdev(struct net_device *dev);
void unregister_netdev(struct net_device *dev);

static inline void dev_put(struct net_device *dev)
{
	free_netdev(dev);
}

static inline void dev_hold(struct net_device *dev)
{
	atomic_inc(&dev->refcnt);
}

struct net_device *dev_get_by_name(struct net *net, const char *name);
struct net_device *dev_get_by_index(struct net *net, int ifindex);

static inline void *dev_get_priv(struct net_device *dev)
{
        return (void *)((char *)dev + sizeof(*dev));
}

int netdev_populate_table(int sizeof_priv, 
                          void (*setup)(struct net_device *));

int dev_queue_xmit(struct sk_buff *skb);

int netdev_init(void);
void netdev_fini(void);

int dev_get_ipv4_addr(struct net_device *dev, void *addr);
int dev_get_ipv4_broadcast(struct net_device *dev, void *addr);

#endif /* OS_USER */

#endif /* _NETDEVICE_H_ */
