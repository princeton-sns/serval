/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SERVICE_H_
#define _SERVICE_H_

#include <scaffold/lock.h>
#include <scaffold/list.h>
#include <scaffold/atomic.h>
#include <scaffold/skbuff.h>
#include <scaffold/dst.h>
#include "bst.h"

struct service_id;

struct service_entry {
	union {
		struct dst_entry dst;
	} u;
        struct bst_node *node;
        struct list_head dev_list, *dev_pos;
        rwlock_t devlock;
        atomic_t refcnt;
};

struct net_device *service_entry_get_dev(struct service_entry *se, 
                                         const char *ifname);
int service_entry_remove_dev(struct service_entry *se, 
                             const char *ifname);
int service_entry_add_dev(struct service_entry *se, 
                          struct net_device *dev,
                          unsigned char *dst,
                          int dstlen,
                          gfp_t alloc);
void service_entry_dev_iterate_begin(struct service_entry *se);
void service_entry_dev_iterate_end(struct service_entry *se);
struct net_device *service_entry_dev_next(struct service_entry *se);
int service_entry_dev_dst(struct service_entry *se, unsigned char *dst, 
                          int dstlen);

int service_add(struct service_id *srvid, unsigned int prefix_size,
		struct net_device *dev, unsigned char *dst,
                int dstlen, gfp_t alloc);
void service_del(struct service_id *srvid, unsigned int prefix_size);
int service_del_dev(const char *devname);
struct service_entry *service_find(struct service_id *srvid);
void service_entry_hold(struct service_entry *se);
void service_entry_put(struct service_entry *se);
int services_print(char *buf, int buflen);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
#define _skb_refdst _skb_dst
#endif

static inline struct service_entry *skb_service_entry(struct sk_buff *skb)
{
        if (skb->_skb_refdst == 0)
                return NULL;
        return (struct service_entry *)skb->_skb_refdst;        
}

static inline void skb_set_service_entry(struct sk_buff *skb, struct service_entry *se)
{
        skb->_skb_refdst = (unsigned long)se;        
}

#endif /* _SERVICE_H_ */
