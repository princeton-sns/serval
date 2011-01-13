/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/platform.h>
#include <scaffold/netdevice.h>
#include <scaffold/atomic.h>
#include <scaffold/debug.h>
#include <scaffold/list.h>
#include <scaffold/lock.h>
#include <scaffold/dst.h>
#include <netinet/scaffold.h>
#if defined(OS_USER)
#include <stdlib.h>
#include <errno.h>
#endif

#include "neighbor.h"
#include "bst.h"

#define get_neighbor(n) bst_node_private(n, struct neighbor_entry)
#define find_neighbor_entry(tbl, prefix, bits) \
        get_neighbor(bst_find_longest_prefix(tbl->tree, prefix, bits))

struct neighbor_table {
        struct bst tree;
        struct bst_node_ops neigh_ops;
        rwlock_t lock;
};

static int neighbor_entry_init(struct bst_node *n);
static void neighbor_entry_destroy(struct bst_node *n);

static struct neighbor_table neightable;

/* 
   The returned net_device will have an increased reference count, so
   a put is necessary following a successful call to this
   function.  
*/
struct net_device *neighbor_entry_get_dev(struct neighbor_entry *neigh)
{
        if (neigh->dev) 
                dev_hold(neigh->dev);
        return neigh->dev;
}

static struct neighbor_entry *neighbor_entry_create(gfp_t alloc, 
                                                    struct net_device *dev, 
                                                    unsigned char *dst, 
                                                    int dstlen)
{
        struct neighbor_entry *neigh;
    
        neigh = (struct neighbor_entry *)MALLOC(sizeof(*neigh) + dstlen, alloc);
        
        if (!neigh)
                return NULL;

        memset(neigh, 0, sizeof(*neigh));
        
        if (dev) {
                dev_hold(dev);
                neigh->dev = dev;
        }
        neigh->dstlen = dstlen;
        memcpy(neigh->dstaddr, dst, dstlen);

        atomic_set(&neigh->refcnt, 1);

        return neigh;
}

int neighbor_entry_init(struct bst_node *n)
{
         return 0;
}

void __neighbor_entry_free(struct neighbor_entry *neigh)
{
        if (neigh->dev)
                dev_put(neigh->dev);
        FREE(neigh);
}

void neighbor_entry_hold(struct neighbor_entry *neigh)
{
        atomic_inc(&neigh->refcnt);
}

void neighbor_entry_put(struct neighbor_entry *neigh)
{
        if (atomic_dec_and_test(&neigh->refcnt))
		__neighbor_entry_free(neigh);
}

static void neighbor_entry_free(struct neighbor_entry *neigh)
{
        neighbor_entry_put(neigh);
}

void neighbor_entry_destroy(struct bst_node *n)
{
        neighbor_entry_put(get_neighbor(n));
}


/* Returns the device default destination during iteration of device
 * list */
int neighbor_entry_get_dst(struct neighbor_entry *neigh, unsigned char *dst, 
                           int dstlen)
{
        if (!dst || dstlen < neigh->dstlen)
                return neigh->dstlen;

        memcpy(dst, neigh->dstaddr, neigh->dstlen);

        return 0;
}

static int __neighbor_entry_print(struct bst_node *n, char *buf, int buflen)
{
#define PREFIX_BUFLEN (sizeof(struct flow_id)*2+4)
        char prefix[PREFIX_BUFLEN];
        struct neighbor_entry *neigh = get_neighbor(n);
        char macstr[18];
        int len = 0;

        bst_node_print_prefix(n, prefix, PREFIX_BUFLEN);
        
        len += snprintf(buf + len, buflen - len, "%-15s %-6u %-18s %-5s\n",
                        prefix, bst_node_prefix_bits(n), 
                        mac_ntop(neigh->dstaddr, macstr, 18),
                        neigh->dev ? neigh->dev->name : "any");
        
        return len;
}

int neighbor_entry_print(struct neighbor_entry *neigh, char *buf, int buflen)
{
        return __neighbor_entry_print(neigh->node, buf, buflen);
}

static int neighbor_table_print(struct neighbor_table *tbl, 
                                char *buf, int buflen)
{
        int ret;

        /* print header */
        ret = snprintf(buf, buflen, "%-15s %-6s %-18s %-5s\n", 
                       "ip prefix", "bits", "mac", "dev");

        read_lock_bh(&tbl->lock);
        ret += bst_print(&tbl->tree, buf + ret, buflen - ret);
        read_unlock_bh(&tbl->lock);
        return ret;
}

int neighbors_print(char *buf, int buflen)
{
        return neighbor_table_print(&neightable, buf, buflen);
}

static struct neighbor_entry *neighbor_table_find(struct neighbor_table *tbl, 
                                                  struct flow_id *flw)
{
        struct neighbor_entry *neigh = NULL;
        struct bst_node *n;

        if (!flw)
                return NULL;

        read_lock_bh(&tbl->lock);
        
        n = bst_find_longest_prefix(&tbl->tree, flw, sizeof(*flw) * 8);

        if (n) {
                neigh = get_neighbor(n);
                neighbor_entry_hold(neigh);
        }

        read_unlock_bh(&tbl->lock);

        return neigh;
}

struct neighbor_entry *neighbor_find(struct flow_id *flw)
{
        return neighbor_table_find(&neightable, flw);
}

int neighbor_table_add(struct neighbor_table *tbl, struct flow_id *flw, 
                       unsigned int prefix_bits, struct net_device *dev,
                       unsigned char *dst, int dstlen,
                       gfp_t alloc)
{
        struct neighbor_entry *neigh;
        struct bst_node *n;
        int ret = 0;

        read_lock_bh(&tbl->lock);
        
        n = bst_find_longest_prefix(&tbl->tree, flw, prefix_bits);

        if (n && bst_node_prefix_bits(n) >= prefix_bits) {
                read_unlock_bh(&tbl->lock);
                LOG_DBG("neighbor entry already in table\n");
                return 0;
        }
        read_unlock_bh(&tbl->lock);
        
        neigh = neighbor_entry_create(alloc, dev, dst, dstlen);
        
        if (!neigh)
                return -ENOMEM;

        ret = 1;


        write_lock_bh(&tbl->lock);
        neigh->node = bst_insert_prefix(&tbl->tree, &tbl->neigh_ops, 
                                        neigh, flw, prefix_bits, alloc);
        write_unlock_bh(&tbl->lock);
        
        if (!neigh->node) {
                neighbor_entry_free(neigh);
                ret = -ENOMEM;
        }

        return ret;
}

int neighbor_add(struct flow_id *flw, unsigned int prefix_bits, 
                 struct net_device *dev, void *dst, 
                 int dstlen, gfp_t alloc)
{
        return neighbor_table_add(&neightable, flw, prefix_bits, 
                                 dev, dst, dstlen, alloc);
}

void neighbor_table_del(struct neighbor_table *tbl, struct flow_id *flw, 
                        unsigned int prefix_bits)
{
        write_lock_bh(&tbl->lock);
        bst_remove_prefix(&tbl->tree, flw, prefix_bits);
        write_unlock_bh(&tbl->lock);
}

void neighbor_del(struct flow_id *flw, unsigned int prefix_bits)
{
        return neighbor_table_del(&neightable, flw, prefix_bits);
}

static int del_dev_func(struct bst_node *n, void *arg)
{
        struct neighbor_entry *neigh = get_neighbor(n);
        char *devname = (char *)arg;
        int ret = 0;

        /* FIXME: make sure we can safely recursively delete nodes in
         * this callback. */
        if (neigh->dev && strcmp(neigh->dev->name, devname) == 0) {
                bst_node_remove(n);
                ret = 1;
        }
        
        return ret;
}

static int neighbor_table_del_dev(struct neighbor_table *tbl, 
                                  const char *devname)
{
        int ret = 0;

        write_lock_bh(&tbl->lock);

        if (tbl->tree.root)
                ret = bst_subtree_func(tbl->tree.root, del_dev_func, 
                                       (void *)devname);
        write_unlock_bh(&tbl->lock);

        return ret;
}

int neighbor_del_dev(const char *devname)
{
        return neighbor_table_del_dev(&neightable, devname);
}

void __neighbor_table_destroy(struct neighbor_table *tbl)
{
        bst_destroy(&tbl->tree);
}

void neighbor_table_destroy(struct neighbor_table *tbl)
{
        write_lock_bh(&tbl->lock);
        __neighbor_table_destroy(tbl);
        write_unlock_bh(&tbl->lock);
}

void neighbor_table_init(struct neighbor_table *tbl)
{
        bst_init(&tbl->tree);
        tbl->neigh_ops.init = neighbor_entry_init;
        tbl->neigh_ops.destroy = neighbor_entry_destroy;
        tbl->neigh_ops.print = __neighbor_entry_print;
        rwlock_init(&tbl->lock);
}

int __init neighbor_init(void)
{
        struct flow_id broadcast;
        unsigned char mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

        neighbor_table_init(&neightable);

        /* Add a default broadcast entry */
        memset(&broadcast, 0xff, sizeof(broadcast));
        neighbor_add(&broadcast, sizeof(broadcast) * 8, NULL, 
                     &mac, 6, GFP_ATOMIC);
        return 0;
}

void __exit neighbor_fini(void)
{
        neighbor_table_destroy(&neightable);
}
