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

/** 
    The service entry contains a list of sets of destinations.
    Each set contains destinations with the same priority.
*/
struct service_entry {
        struct bst_node *node;
        struct list_head target_set;
        unsigned int count;
        atomic_t packets_resolved;
        atomic_t bytes_resolved;
        atomic_t bytes_dropped;
        atomic_t packets_dropped;
        rwlock_t lock;
        atomic_t refcnt;
};

/**
   Iterator for the service table. 

   Iterates through all destinations in all sets, or only one set with
   a particular priority.
*/
struct service_resolution_iter {
        struct service_entry* entry;
        struct target_set *set;
        struct list_head *pos;
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

/**
   Statistics for each target.
*/
struct target_stats {
        uint32_t duration_sec;
        uint32_t duration_nsec;
        uint32_t packets_resolved;
        uint32_t bytes_resolved;
        uint32_t packets_dropped;
        uint32_t bytes_dropped;
};

/**
   A set of destinations sharing the same priority.
*/
struct target_set {
        struct list_head lh;
        struct list_head list;
        uint32_t normalizer;
        uint32_t priority;
        uint16_t flags;
        uint16_t count;
};

#define is_sock_target(target) ((target)->dstlen == 0)

union target_out {
        void *raw;
        struct net_device *dev;
        struct sock *sk;
};

static inline union target_out make_target(void *t)
{
        union target_out out = { t };
        return out;
}

/**
   A destination, either a local socket or remote host.
*/
struct target {
        struct list_head lh;
        uint32_t weight;
        atomic_t packets_resolved;
        atomic_t bytes_resolved;
        atomic_t bytes_dropped;
        atomic_t packets_dropped;
        union target_out out;
        int dstlen;
        unsigned char dst[0]; /* Must be last */
};

typedef enum {
        SERVICE_ENTRY_LOCAL,
        SERVICE_ENTRY_GLOBAL,
        SERVICE_ENTRY_ANY,
        SERVICE_ENTRY_EXACT,
} service_entry_type_t;

void service_inc_stats(int packets, int bytes);
void service_get_stats(struct table_stats* tstats);

struct net_device *service_entry_get_dev(struct service_entry *se,
                                         const char *ifname);
int service_entry_remove_target_by_dev(struct service_entry *se,
                                       const char *ifname);

int service_entry_remove_target(struct service_entry *se,
                                const void *dst, int dstlen, 
                                struct target_stats *stats);

int service_entry_add_target(struct service_entry *se,
                             uint16_t flags,
                             uint32_t priority,
                             uint32_t weight,
                             const void *dst,
                             int dstlen,
                             const union target_out out,
                             gfp_t alloc);

int service_entry_modify_target(struct service_entry *se,
                                uint16_t flags,
                                uint32_t priority,
                                uint32_t weight,
                                const void *dst,
                                int dstlen,
                                const void *new_dst,
                                int new_dstlen,
                                const union target_out out,
                                gfp_t alloc);

void service_entry_inc_target_stats(struct service_entry *se, const void *dst, 
                                    int dstlen, int packets, int bytes);

typedef enum {
        SERVICE_ITER_ALL, /* Return all entries */
        SERVICE_ITER_ANYCAST, /* Only top priority entries */
} iter_mode_t;

void service_resolution_iter_init(struct service_resolution_iter *iter, 
                                  struct service_entry *se, iter_mode_t mode);
void service_resolution_iter_destroy(struct service_resolution_iter *iter);
struct target *service_resolution_iter_next(struct service_resolution_iter *iter);
void service_resolution_iter_inc_stats(struct service_resolution_iter *iter, 
                                       int packets, int bytes);
int service_resolution_iter_get_priority(struct service_resolution_iter *iter);
int service_resolution_iter_get_flags(struct service_resolution_iter *iter);

int service_entry_target_fill(struct service_entry *se, void *dst,
                              int dstlen);

int service_get_id(const struct service_entry *se, struct service_id *srvid);
unsigned char service_get_prefix_bits(const struct service_entry *se);

int service_add(struct service_id *srvid, uint16_t prefix_bits, 
                uint16_t flags, uint32_t priority, uint32_t weight,
		const void *dst, int dstlen, const union target_out out, 
                gfp_t alloc);

int service_modify(struct service_id *srvid, uint16_t prefix_bits, 
                   uint16_t flags, uint32_t priority, uint32_t weight,
                   const void *dst, int dstlen, 
                   const void *new_dst, int new_dstlen,
                   const union target_out out);

void service_del(struct service_id *srvid, uint16_t prefix_bits);
void service_del_target(struct service_id *srvid, uint16_t prefix_bits,
                        const void *dst, int dstlen, 
                        struct target_stats *stats);

int service_del_target_all(const void *dst, int dstlen);
int service_del_dev_all(const char *devname);

struct service_entry *service_find_type(struct service_id *srvid,
                                        int prefix,
                                        service_entry_type_t type);

static 
inline struct service_entry *service_find(struct service_id *srvid, 
                                          int prefix)
{
        return service_find_type(srvid, prefix, SERVICE_ENTRY_ANY);
}

static 
inline struct service_entry *service_find_exact(struct service_id *srvid, 
                                                int prefix)
{
        return service_find_type(srvid, prefix, SERVICE_ENTRY_EXACT);
}

struct sock *service_find_sock(struct service_id *srvid, int prefix, int protocol);

void service_entry_hold(struct service_entry *se);
void service_entry_put(struct service_entry *se);
int service_entry_print(struct service_entry *se, char *buf, int buflen);

void service_table_read_lock(void);
void service_table_read_unlock(void);
int __service_table_print(char *buf, int buflen);
int service_table_print(char *buf, int buflen);

#endif /* _SERVICE_H_ */
