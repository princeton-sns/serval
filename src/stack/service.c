/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/platform.h>
#include <serval/netdevice.h>
#include <serval/atomic.h>
#include <serval/debug.h>
#include <serval/list.h>
#include <serval/lock.h>
#include <serval/dst.h>
#include <netinet/serval.h>
#if defined(OS_USER)
#include <stdlib.h>
#include <errno.h>
#endif

#include "service.h"
#include "bst.h"

#define get_service(n) bst_node_private(n, struct service_entry)
#define find_service_entry(tbl, prefix, bits) \
        get_service(bst_find_longest_prefix(tbl->tree, prefix, bits))

struct service_table {
        struct bst tree;
        struct bst_node_ops srv_ops;
        rwlock_t lock;
};

static int service_entry_init(struct bst_node *n);
static void service_entry_destroy(struct bst_node *n);

/*
static void dest_destroy(struct dest *dst)
{
        service_entry_put((struct service_entry *)dst);
}

static struct dst_ops service_dst_ops = {
	.family =		AF_SERVAL,
	.protocol =		cpu_to_be16(ETH_P_IP),
        .destroy =              dest_destroy
};
*/
static struct service_table srvtable;

static struct dest *dest_create(const void *dst,
                                int dstlen,
                                struct net_device *dev, 
                                gfp_t alloc)
{
        struct dest *de;

        de = (struct dest *)MALLOC(sizeof(*de) + dstlen, alloc);

        if (!de)
                return NULL;

        memset(de, 0, sizeof(*de) + dstlen);
        if (dev) {
                de->dev = dev;
                dev_hold(dev);
        }
        de->dstlen = dstlen;
        memcpy(de->dst, dst, dstlen);
        INIT_LIST_HEAD(&de->lh);
        
        return de;
}

static void dest_free(struct dest *de)
{
        if (de->dev)
                dev_put(de->dev);
        FREE(de);
}


/*
static void __service_entry_remove_dest(struct service_entry *se, 
                                                struct dest *de)
{
        struct dest *de;
        
        write_lock(&se->destlock);
        list_del(&de->lh);
        write_unlock(&se->destlock);
}
*/

static struct net_device *__service_entry_get_dev(struct service_entry *se, 
                                                  const char *ifname)
{
        struct dest *de;
        struct net_device *dev = NULL;

        list_for_each_entry(de, &se->dest_list, lh) {
                if (de->dev && strcmp(de->dev->name, ifname) == 0) {
                        dev = de->dev;
                        break;
                } 
        }

        return dev;
}

static struct dest *__service_entry_get_dest(struct service_entry *se, 
                                              const void *dst, int dstlen)
{
        struct dest *de = NULL;

        list_for_each_entry(de, &se->dest_list, lh) {
                if (memcmp(de->dst, dst, dstlen) == 0) {
                        return de;
                } 
        }

        return NULL;
}

/* 
   The returned net_device will have an increased reference count, so
   a put is necessary following a successful call to this
   function.  
*/
struct net_device *service_entry_get_dev(struct service_entry *se, 
                                         const char *ifname)
{
        struct net_device *dev = NULL;

        read_lock(&se->destlock);
        
        dev = __service_entry_get_dev(se, ifname);

        if (dev)
                dev_hold(dev);

        read_unlock(&se->destlock);

        return dev;
}

static int __service_entry_add_dest(struct service_entry *se, 
                                    const void *dst,
                                    int dstlen,
                                    struct net_device *dev, 
                                    gfp_t alloc)
{
        struct dest *de;

        if (__service_entry_get_dest(se, dst, dstlen))
                return 0;

        de = dest_create(dst, dstlen, dev, alloc);

        if (!de)
                return -ENOMEM;

        list_add_tail(&de->lh, &se->dest_list);

        return 1;
}

int service_entry_add_dest(struct service_entry *se, 
                           const void *dst,
                           int dstlen,
                           struct net_device *dev,
                           gfp_t alloc)
{
        int ret = 0;
        
        write_lock(&se->destlock);
        ret = __service_entry_add_dest(se, dst, dstlen, dev, GFP_ATOMIC);
        write_unlock(&se->destlock);

        return ret;
}

int __service_entry_remove_dest_by_dev(struct service_entry *se, 
                                       const char *ifname)
{
        struct dest *de;

        list_for_each_entry(de, &se->dest_list, lh) {
                if (de->dev && strcmp(de->dev->name, ifname) == 0) {
                        list_del(&de->lh);
                        dest_free(de);
                        return 1;
                } 
        }
        return 0;
}

int service_entry_remove_dest_by_dev(struct service_entry *se, 
                                     const char *ifname)
{        
        int ret;
        write_lock(&se->destlock);
        ret = __service_entry_remove_dest_by_dev(se, ifname);
        write_unlock(&se->destlock);
        return ret;
}

int __service_entry_remove_dest(struct service_entry *se, 
                                const void *dst, int dstlen)
{
        struct dest *de;

        list_for_each_entry(de, &se->dest_list, lh) {
                if (memcmp(de->dst, dst, dstlen) == 0) {
                        list_del(&de->lh);
                        dest_free(de);
                        return 1;
                }
        }
        return 0;
}

int service_entry_remove_dest(struct service_entry *se, 
                              const void *dst, int dstlen)
{        
        int ret;
        write_lock(&se->destlock);
        ret = __service_entry_remove_dest(se, dst, dstlen);
        write_unlock(&se->destlock);
        return ret;
}

static struct service_entry *service_entry_create(struct sock *sk, gfp_t alloc)
{
        struct service_entry *se;
    
        se = (struct service_entry *)MALLOC(sizeof(*se), alloc);
        
        if (!se)
                return NULL;

        memset(se, 0, sizeof(*se));
        INIT_LIST_HEAD(&se->dest_list);
        rwlock_init(&se->destlock);
        atomic_set(&se->refcnt, 1);
        se->dest_pos = NULL;

        if (sk) {
                se->sk = sk;
                sock_hold(sk);
        } else {
                se->sk = NULL;
        }

        return se;
}

int service_entry_init(struct bst_node *n)
{
         return 0;
}

void __service_entry_free(struct service_entry *se)
{
        while (1) {
                struct dest *de;
                
                if (list_empty(&se->dest_list))
                        break;
                
                de = list_first_entry(&se->dest_list, struct dest, lh);
                list_del(&de->lh);
                dest_free(de);
        }

        if (se->sk)
                sock_put(se->sk);

        rwlock_destroy(&se->destlock);

        FREE(se);
}

void service_entry_hold(struct service_entry *se)
{
        atomic_inc(&se->refcnt);
}

void service_entry_put(struct service_entry *se)
{
        if (atomic_dec_and_test(&se->refcnt))
		__service_entry_free(se);
}

static void service_entry_free(struct service_entry *se)
{
        service_entry_put(se);
}

void service_entry_destroy(struct bst_node *n)
{
        service_entry_put(get_service(n));
}

void service_entry_dest_iterate_begin(struct service_entry *se)
{
        read_lock_bh(&se->destlock);
        se->dest_pos = &se->dest_list;
}

void service_entry_dest_iterate_end(struct service_entry *se)
{
        se->dest_pos = NULL;
        read_unlock_bh(&se->destlock);
}

/* 
   Calls to this function must be preceeded by a call to
   service_entry_dest_iterate_begin() and followed by
   service_entry_dest_iterate_end(). 
*/
struct dest *service_entry_dest_next(struct service_entry *se)
{
        se->dest_pos = se->dest_pos->next;

        if (se->dest_pos == &se->dest_list)
                return NULL;

        return container_of(se->dest_pos, struct dest, lh);
}

/* Fills in the destination during iteration of destination list */
int service_entry_dest_fill(struct service_entry *se, void *dst, int dstlen)
{
        struct dest *de;

        if (!se->dest_pos)
                return -1;
        
        de = container_of(se->dest_pos, struct dest, lh);
        
        if (!dst || dstlen < de->dstlen)
                return de->dstlen;

        memcpy(dst, de->dst, de->dstlen);
       
        return 0;
}

static int __service_entry_print(struct bst_node *n, char *buf, int buflen)
{
#define PREFIX_BUFLEN (sizeof(struct service_id)*2+4)
        char prefix[PREFIX_BUFLEN];
        struct service_entry *se = get_service(n);
        struct dest *de;
        char dststr[18]; /* Currently sufficient for IPv4 */
        int len = 0;

        read_lock_bh(&se->destlock);

        bst_node_print_prefix(n, prefix, PREFIX_BUFLEN);
        
        len += snprintf(buf + len, buflen - len, "%-64s %-6u %-4u ",
                        prefix, bst_node_prefix_bits(n), 
                        se->sk ? 1 : 0);

        list_for_each_entry(de, &se->dest_list, lh) {
                len += snprintf(buf + len, buflen - len, "[%-5s %s] ",
                                de->dev ? de->dev->name : "any",
                                inet_ntop(AF_INET, de->dst, dststr, 18));
        }

        /* remove last whitespace */
        len--;
        len += snprintf(buf + len, buflen - len, "\n");

        read_unlock_bh(&se->destlock);

        return len;
}

int service_entry_print(struct service_entry *se, char *buf, int buflen)
{
        return __service_entry_print(se->node, buf, buflen);
}

static int service_table_print(struct service_table *tbl, char *buf, int buflen)
{
        int ret;

        /* print header */
        ret = snprintf(buf, buflen, "%-64s %-6s %-4s [iface dst]\n", 
                       "prefix", "bits", "sock");

        read_lock_bh(&tbl->lock);
        ret += bst_print(&tbl->tree, buf + ret, buflen - ret);
        read_unlock_bh(&tbl->lock);
        return ret;
}

int services_print(char *buf, int buflen)
{
        return service_table_print(&srvtable, buf, buflen);
}


static int service_entry_local_match(struct bst_node *n)
{
        struct service_entry *se = get_service(n);
        
        if (se->sk)
                return 1;

        return 0;
}

static int service_entry_global_match(struct bst_node *n)
{
        struct service_entry *se = get_service(n);
        
        if (!se->sk)
                return 1;

        return 0;
}

static int service_entry_any_match(struct bst_node *n)
{
        return 1;
}

static struct service_entry *service_table_find(struct service_table *tbl, 
                                                struct service_id *srvid, 
                                                service_entry_type_t type)
{
        struct service_entry *se = NULL;
        struct bst_node *n;
        int (*match)(struct bst_node *) = NULL;

        if (!srvid)
                return NULL;

        switch (type) {
        case SERVICE_ENTRY_LOCAL:
                match = service_entry_local_match;
                break;
        case SERVICE_ENTRY_GLOBAL:
                match = service_entry_global_match;
                break;
        case SERVICE_ENTRY_ANY:
                match = service_entry_any_match;
                break;
        }

        read_lock_bh(&tbl->lock);
        
        n = bst_find_longest_prefix_match(&tbl->tree, srvid, 
                                          sizeof(*srvid) * 8,
                                          match);

        if (n) {
                se = get_service(n);
                service_entry_hold(se);
        }

        read_unlock_bh(&tbl->lock);

        return se;
}

struct service_entry *service_find_type(struct service_id *srvid, 
                                        service_entry_type_t type)
{
        return service_table_find(&srvtable, srvid, type);
}

static int service_table_add(struct service_table *tbl, 
                             struct service_id *srvid, 
                             unsigned int prefix_bits,
                             const void *dst, 
                             int dstlen, 
                             struct net_device *dev,
                             struct sock *sk,
                             gfp_t alloc)
{
        struct service_entry *se;
        struct bst_node *n;
        int ret = 0;

        write_lock_bh(&tbl->lock);
        
        n = bst_find_longest_prefix(&tbl->tree, srvid, prefix_bits);

        if (n && bst_node_prefix_bits(n) >= prefix_bits) {
                if (sk) {
                        ret = -EADDRINUSE;
                        goto out;
                }
                if (dst) {
                        if (get_service(n)->sk) {
                                ret = -EADDRINUSE;
                                goto out;
                        }
                        ret = __service_entry_add_dest(get_service(n), 
                                                       dst,
                                                       dstlen,
                                                       dev,
                                                       GFP_ATOMIC);
                }
                goto out;
        }
        
        se = service_entry_create(sk, GFP_ATOMIC);
        
        if (!se) {
                ret = -ENOMEM;
                goto out;
        }
        
        if (dst) {
                ret = __service_entry_add_dest(se, dst, dstlen, dev, GFP_ATOMIC);

                if (ret < 0) {
                        service_entry_free(se);
                        ret = -ENOMEM;
                        goto out;
                }
        }
        se->node = bst_insert_prefix(&tbl->tree, &tbl->srv_ops, 
                                     se, srvid, prefix_bits, GFP_ATOMIC);
                
        if (!se->node) {
                service_entry_free(se);
                ret = -ENOMEM;
        }
out:  
        write_unlock_bh(&tbl->lock);

        return ret;
}

int service_add(struct service_id *srvid, unsigned int prefix_bits, 
                const void *dst, int dstlen, struct net_device *dev,
                struct sock *sk, gfp_t alloc)
{
        return service_table_add(&srvtable, srvid, prefix_bits, 
                                 dst, dstlen, dev, sk, alloc);
}

static void service_table_del(struct service_table *tbl, 
                              struct service_id *srvid, 
                              unsigned int prefix_bits)
{
        write_lock_bh(&tbl->lock);
        bst_remove_prefix(&tbl->tree, srvid, prefix_bits);
        write_unlock_bh(&tbl->lock);
}

void service_del(struct service_id *srvid, unsigned int prefix_bits)
{
        return service_table_del(&srvtable, srvid, prefix_bits);
}

static void service_table_del_dest(struct service_table *tbl, 
                                   struct service_id *srvid, 
                                   unsigned int prefix_bits, 
                                   const void *dst, int dstlen)
{
        struct bst_node *n;

        if (!dst || dstlen == 0)
                return service_table_del(tbl, srvid, prefix_bits);

        write_lock_bh(&tbl->lock);
        
        n = bst_find_longest_prefix(&tbl->tree, srvid, prefix_bits);

        if (n) { 
                write_lock_bh(&get_service(n)->destlock);
                __service_entry_remove_dest(get_service(n), dst, dstlen);
                write_unlock_bh(&get_service(n)->destlock);
        
                if (list_empty(&get_service(n)->dest_list))
                        bst_node_remove(n);
        }

        write_unlock_bh(&tbl->lock);
}

void service_del_dest(struct service_id *srvid, unsigned int prefix_bits,
                      const void *dst, int dstlen)
{
        return service_table_del_dest(&srvtable, srvid, prefix_bits, 
                                      dst, dstlen);
}

static int del_dev_func(struct bst_node *n, void *arg)
{
        struct service_entry *se = get_service(n);
        char *devname = (char *)arg;
        int ret = 0, should_remove = 0;
        
        write_lock_bh(&se->destlock);
        
        ret = __service_entry_remove_dest_by_dev(se, devname);

        if (ret == 1 && list_empty(&se->dest_list))
                should_remove = 1;

        write_unlock_bh(&se->destlock);

        if (should_remove)
                bst_node_remove(n);
        
        return ret;
}

static int service_table_del_dev_all(struct service_table *tbl, 
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

int service_del_dev_all(const char *devname)
{
        return service_table_del_dev_all(&srvtable, devname);
}

static int del_dest_func(struct bst_node *n, void *arg)
{
        struct service_entry *se = get_service(n);
        struct _d {
                const void *d_dst;
                int d_len;
        } *d = (struct _d *)arg;
        int ret = 0, should_remove = 0;
        
        write_lock_bh(&se->destlock);
        
        ret = __service_entry_remove_dest(se, d->d_dst, d->d_len);

        if (ret == 1 && list_empty(&se->dest_list))
                should_remove = 1;

        write_unlock_bh(&se->destlock);

        if (should_remove)
                bst_node_remove(n);
        
        return ret;
}

static int service_table_del_dest_all(struct service_table *tbl, 
                                      const void *dst, int dstlen)
{
        int ret = 0;
        struct {
                const void *d_dst;
                int d_len;
        } d = { dst, dstlen };

        write_lock_bh(&tbl->lock);

        if (tbl->tree.root)
                ret = bst_subtree_func(tbl->tree.root, del_dest_func, &d);

        write_unlock_bh(&tbl->lock);

        return ret;
}

int service_del_dest_all(const void *dst, int dstlen)
{
        return service_table_del_dest_all(&srvtable, dst, dstlen);
}

void __service_table_destroy(struct service_table *tbl)
{
        bst_destroy(&tbl->tree);
}

void service_table_destroy(struct service_table *tbl)
{
        write_lock_bh(&tbl->lock);
        __service_table_destroy(tbl);
        write_unlock_bh(&tbl->lock);
}

void service_table_init(struct service_table *tbl)
{
        bst_init(&tbl->tree);
        tbl->srv_ops.init = service_entry_init;
        tbl->srv_ops.destroy = service_entry_destroy;
        tbl->srv_ops.print = __service_entry_print;
        rwlock_init(&tbl->lock);
}
/*
#if defined(OS_USER)
struct kmem_cache kmem_cachep = {
        .size = sizeof(struct service_entry)
};
#endif
*/
int __init service_init(void)
{
/*
#if defined(OS_LINUX_KERNEL)
        service_dst_ops.kmem_cachep =
		kmem_cache_create("service_dst_cache", 
                                  sizeof(struct service_entry), 0,
				  SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);
#else        
        service_dst_ops.kmem_cachep = &kmem_cachep;
#endif
*/
        service_table_init(&srvtable);

        return 0;
}

void __exit service_fini(void)
{
        service_table_destroy(&srvtable);
}
