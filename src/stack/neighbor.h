/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _NEIGHBOR_H_
#define _NEIGHBOR_H_

#include <scaffold/lock.h>
#include <scaffold/list.h>
#include <scaffold/atomic.h>
#include <scaffold/skbuff.h>
#include <scaffold/dst.h>
#include "bst.h"

struct flow_id;

struct neighbor_entry {
	union {
		struct dst_entry dst;
	} u;
        struct bst_node *node;
        atomic_t refcnt;
        struct net_device *dev;
        int dstlen;
        unsigned char dstaddr[]; /* Must be last */
};

struct net_device *neighbor_entry_get_dev(struct neighbor_entry *neigh);
int neighbor_entry_get_dst(struct neighbor_entry *neigh, unsigned char *dst, 
                           int dstlen);

int neighbor_add(struct flow_id *flw, unsigned int prefix_size,
		struct net_device *dev, unsigned char *dst,
                int dstlen, gfp_t alloc);
void neighbor_del(struct flow_id *flw, unsigned int prefix_size);
int neighbor_del_dev(const char *devname);
struct neighbor_entry *neighbor_find(struct flow_id *flw);
void neighbor_entry_hold(struct neighbor_entry *neigh);
void neighbor_entry_put(struct neighbor_entry *neigh);
int neighbor_entry_print(struct neighbor_entry *neigh, char *buf, int buflen);
int neighbors_print(char *buf, int buflen);

static inline struct neighbor_entry *skb_neighbor_entry(struct sk_buff *skb)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
#define _skb_refdst dst
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
#define _skb_refdst _skb_dst
#endif
        if (skb->_skb_refdst == 0)
                return NULL;
        return (struct neighbor_entry *)skb->_skb_refdst;        
}

static inline void skb_set_neighbor_entry(struct sk_buff *skb, 
                                          struct neighbor_entry *neigh)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
        skb->dst = (struct dst_entry *)neigh;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
        skb->_skb_dst = (unsigned long)neigh;
#else
        skb->_skb_refdst = (unsigned long)neigh;
#endif
}

#endif /* _NEIGHBOR_H_ */
