/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SERVICE_H_
#define _SERVICE_H_

#include <serval/lock.h>
#include <serval/list.h>
#include <serval/atomic.h>
#include <serval/skbuff.h>
#include <serval/dst.h>
#include <serval/sock.h>
#include "bst.h"

#define LOCAL_SERVICE_DEFAULT_PRIORITY 32000
#define LOCAL_SERVICE_DEFAULT_WEIGHT 1024

#define BROADCAST_SERVICE_DEFAULT_PRIORITY 1
#define BROADCAST_SERVICE_DEFAULT_WEIGHT 1

struct service_id;

struct service_entry {
	union {
		struct dst_entry dst;
	} u;
        struct bst_node *node;

        //struct list_head dest_list, *dest_pos;
        struct list_head dest_set;

        int count;
        //struct sock *sk;
        atomic_t packets_resolved;
        atomic_t bytes_resolved;
        atomic_t bytes_dropped;
        atomic_t packets_dropped;
        rwlock_t destlock;
        atomic_t refcnt;
};

struct service_resolution_iter {
    struct service_entry* entry;
    struct dest_set* destset;
    struct list_head *dest_pos;
    struct list_head *last_pos;
};

struct table_stats {
    uint32_t instances;
    uint32_t services;
    uint32_t packets_resolved;
    uint32_t bytes_resolved;
    uint32_t packets_dropped;
    uint32_t bytes_dropped;
};

/* TODO - should this include the device ifindex?*/
struct dest_stats {
    uint32_t duration_sec;
    uint32_t duration_nsec;
    uint32_t packets_resolved;
    uint32_t bytes_resolved;
    uint32_t packets_dropped;
    uint32_t bytes_dropped;
};

struct dest_set {
        struct list_head ds;
        struct list_head dest_list;
        uint32_t normalizer;
        uint32_t priority;
        uint16_t flags;
        uint16_t count;
};

#define is_sock_dest(dest) (dest->dstlen == 0)

struct dest {
        struct list_head lh;
        uint32_t weight;
        atomic_t packets_resolved;
        atomic_t bytes_resolved;
        atomic_t bytes_dropped;
        atomic_t packets_dropped;

        union {
            struct net_device *dev;
            struct sock *sk;
        } dest_out;
        int dstlen;
        unsigned char dst[0]; /* Must be last */
};

typedef enum {
        SERVICE_ENTRY_LOCAL,
        SERVICE_ENTRY_GLOBAL,
        SERVICE_ENTRY_ANY,
} service_entry_type_t;

void service_inc_stats(int packets, int bytes);
void service_get_stats(struct table_stats* tstats);
struct net_device *service_entry_get_dev(struct service_entry *se,
                                         const char *ifname);
int service_entry_remove_dest_by_dev(struct service_entry *se,
                                     const char *ifname);
//int service_entry_remove_dest_by_sock(struct service_entry *se,
//                                     struct sock *sk);

int service_entry_remove_dest(struct service_entry *se,
                              const void *dst, int dstlen, struct dest_stats* dstats);

int service_entry_add_dest(struct service_entry *se,
                           uint16_t flags,
                           uint32_t priority,
                           uint32_t weight,
                           const void *dst,
                           int dstlen,
                           const void *dest_out,
                           gfp_t alloc);
int service_entry_modify_dest(struct service_entry *se,
                           uint16_t flags,
                           uint32_t priority,
                           uint32_t weight,
                           const void *dst,
                           int dstlen,
                           const void *dest_out);
void service_entry_inc_dest_stats(struct service_entry *se, const void* dst, int dstlen, int packets, int bytes);
//void service_entry_dest_iterate_begin(struct service_entry *se);
//void service_entry_dest_iterate_end(struct service_entry *se);
//struct dest *service_entry_dest_next(struct service_entry *se);

void service_resolution_iter_init(struct service_resolution_iter* iter, struct service_entry *se, int all);
void service_resolution_iter_destroy(struct service_resolution_iter* iter);
struct dest *service_resolution_iter_next(struct service_resolution_iter* iter);
void service_resolution_iter_inc_stats(struct service_resolution_iter* iter, int packets, int bytes);
int service_resolution_iter_get_priority(struct service_resolution_iter* iter);
int service_resolution_iter_get_flags(struct service_resolution_iter* iter);

int service_entry_dest_fill(struct service_entry *se, void *dst,
                            int dstlen);

int service_add(struct service_id *srvid, uint16_t prefix_bits, 
                uint16_t flags, uint32_t priority, uint32_t weight,
		const void *dst, int dstlen, const void* dest_out, gfp_t alloc);

int service_modify(struct service_id *srvid, uint16_t prefix_bits, 
                   uint16_t flags, uint32_t priority, uint32_t weight,
                   const void *dst, int dstlen, const void* dest_out);

void service_del(struct service_id *srvid, uint16_t prefix_bits);
void service_del_dest(struct service_id *srvid, uint16_t prefix_bits,
                      const void *dst, int dstlen, struct dest_stats* stats);

int service_del_dest_all(const void *dst, int dstlen);
int service_del_dev_all(const char *devname);

struct service_entry *service_find_type(struct service_id *srvid, 
                                        int prefix,
                                        service_entry_type_t type);

static inline struct service_entry *service_find(struct service_id *srvid, 
                                                 int prefix)
{
        return service_find_type(srvid, prefix, SERVICE_ENTRY_ANY);
}

struct sock *service_find_sock(struct service_id *srvid, int prefix);

void service_entry_hold(struct service_entry *se);
void service_entry_put(struct service_entry *se);
int service_entry_print(struct service_entry *se, char *buf, int buflen);
int services_print(char *buf, int buflen);

static inline struct service_entry *skb_service_entry(struct sk_buff *skb)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
#define _skb_refdst dst
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
#define _skb_refdst _skb_dst
#endif
        if (skb->_skb_refdst == 0)
                return NULL;
        return (struct service_entry *)skb->_skb_refdst;
}

static inline void skb_set_service_entry(struct sk_buff *skb,
                                         struct service_entry *se)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
        skb->dst = (struct dst_entry *)se;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
        skb->_skb_dst = (unsigned long)se;
#else
        skb->_skb_refdst = (unsigned long)se;
#endif
}

#endif /* _SERVICE_H_ */
