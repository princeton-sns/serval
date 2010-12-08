/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/platform.h>
#include <scaffold/netdevice.h>
#include <scaffold/atomic.h>
#include <scaffold/debug.h>
#include <scaffold/list.h>
#include <scaffold/lock.h>
#include <netinet/scaffold.h>
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

struct dev_entry {
        struct net_device *dev;
        struct list_head lh;
};

static int service_entry_init(struct bst_node *n);
static void service_entry_destroy(struct bst_node *n);

static struct service_table srvtable;

static struct dev_entry *dev_entry_create(struct net_device *dev, gfp_t alloc)
{
        struct dev_entry *de;

        de = (struct dev_entry *)MALLOC(sizeof(*de), alloc);

        if (!de)
                return NULL;

        memset(de, 0, sizeof(*de));

        de->dev = dev;
        dev_hold(dev);
        INIT_LIST_HEAD(&de->lh);
        
        return de;
}

static void dev_entry_free(struct dev_entry *de)
{
        dev_put(de->dev);
        FREE(de);
}

static int __service_entry_add_dev(struct service_entry *se, 
                                   struct net_device *dev, 
                                   gfp_t alloc)
{
        struct dev_entry *de;

        de = dev_entry_create(dev, alloc);

        if (!de)
                return -ENOMEM;

        list_add_tail(&de->lh, &se->dev_list);

        return 0;
}

int service_entry_add_dev(struct service_entry *se, 
                          struct net_device *dev, 
                          gfp_t alloc)
{
        int ret;
        
        write_lock(&se->devlock);
        ret = __service_entry_add_dev(se, dev, alloc);
        write_unlock(&se->devlock);

        return ret;
}


/*
static void __service_entry_remove_dev_entry(struct service_entry *se, 
                                                struct dev_entry *de)
{
        struct dev_entry *de;
        
        write_lock(&se->devlock);
        list_del(&de->lh);
        write_unlock(&se->devlock);
}
*/

/* 
   The returned net_device will have an increased reference count, so
   a put is necessary following a successful call to this
   function.  
*/
struct net_device *service_entry_get_dev(struct service_entry *se, 
                                         const char *ifname)
{
        struct dev_entry *de;
        struct net_device *dev = NULL;

        read_lock(&se->devlock);

        list_for_each_entry(de, &se->dev_list, lh) {
                if (strcmp(de->dev->name, ifname) == 0) {
                        dev = de->dev;
                        dev_hold(dev);
                        break;
                } 
        }

        read_unlock(&se->devlock);

        return dev;
}

int __service_entry_remove_dev(struct service_entry *se, 
                               const char *ifname)
{
        struct dev_entry *de;

        list_for_each_entry(de, &se->dev_list, lh) {
                if (strcmp(de->dev->name, ifname) == 0) {
                        list_del(&de->lh);
                        dev_entry_free(de);
                        return 1;
                } 
        }
        return 0;
}

int service_entry_remove_dev(struct service_entry *se, 
                             const char *ifname)
{        
        int ret;
        write_lock(&se->devlock);
        ret = __service_entry_remove_dev(se, ifname);
        write_unlock(&se->devlock);
        return ret;
}

static struct service_entry *service_entry_create(gfp_t alloc)
{
        struct service_entry *se;
    
        se = (struct service_entry *)MALLOC(sizeof(*se), alloc);
        
        if (!se)
                return NULL;

        memset(se, 0, sizeof(*se));
        INIT_LIST_HEAD(&se->dev_list);
        rwlock_init(&se->devlock);
        atomic_set(&se->refcnt, 1);
        se->dev_pos = NULL;

        return se;
}

int service_entry_init(struct bst_node *n)
{
         return 0;
}

void __service_entry_free(struct service_entry *se)
{
        /* No locking should be necessary here since we are protected
         * by the reference count. If refrence count is zero, there is
         * only one thread with a reference to this entry. 
         */

        while (1) {
                struct dev_entry *de;
                
                if (list_empty(&se->dev_list))
                        break;
                
                de = list_first_entry(&se->dev_list, struct dev_entry, lh);
                list_del(&de->lh);
                dev_entry_free(de);
        }

        rwlock_destroy(&se->devlock);

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

void service_entry_dev_iterate_begin(struct service_entry *se)
{
        read_lock_bh(&se->devlock);
        se->dev_pos = &se->dev_list;
}

void service_entry_dev_iterate_end(struct service_entry *se)
{
        se->dev_pos = NULL;
        read_unlock_bh(&se->devlock);
}

/* 
   Calling this function must be preceeded by a call to
   service_entry_dev_iterate_begin() and followed by
   service_entry_dev_iterate_end(). 
*/
struct net_device *service_entry_dev_next(struct service_entry *se)
{
        se->dev_pos = se->dev_pos->next;

        if (se->dev_pos == &se->dev_list)
                return NULL;

        return container_of(se->dev_pos, struct dev_entry, lh)->dev;
}


int service_entry_print(struct bst_node *n, char *buf, int buflen)
{
        struct service_entry *se = get_service(n);
        struct dev_entry *de;
        int len = 0;

        read_lock_bh(&se->devlock);
        
        list_for_each_entry(de, &se->dev_list, lh) {
                len += snprintf(buf + len, buflen - len, "%s ", de->dev->name);
        }

        /* remove last whitespace */
        len--;
        read_unlock_bh(&se->devlock);

        return len;
}

static int service_table_print(struct service_table *tbl, char *buf, int buflen)
{
        int ret;

        read_lock_bh(&tbl->lock);
        ret = bst_print(&tbl->tree, buf, buflen);
        read_unlock_bh(&tbl->lock);
        return ret;
}

int services_print(char *buf, int buflen)
{
        LOG_DBG("service table entries=%u\n", srvtable.tree.entries);
        return service_table_print(&srvtable, buf, buflen);
}

static struct service_entry *service_table_find(struct service_table *tbl, 
                                                struct service_id *srvid)
{
        struct service_entry *se = NULL;
        struct bst_node *n;

        if (!srvid)
                return NULL;

        read_lock_bh(&tbl->lock);
        
        n = bst_find_longest_prefix(&tbl->tree, srvid, sizeof(*srvid) * 8);

        if (n) {
                se = get_service(n);
                service_entry_hold(se);
        }

        read_unlock_bh(&tbl->lock);

        return se;
}

struct service_entry *service_find(struct service_id *srvid)
{
        return service_table_find(&srvtable, srvid);
}

int service_table_add(struct service_table *tbl, struct service_id *srvid, 
                      unsigned int prefix_size, struct net_device *dev, 
                      gfp_t alloc)
{
        struct service_entry *se;
        struct bst_node *n;

        int ret;

        read_lock_bh(&tbl->lock);
        
        n = bst_find_longest_prefix(&tbl->tree, srvid, prefix_size);

        if (n) {
                ret = __service_entry_add_dev(get_service(n), dev, alloc);
                read_unlock_bh(&tbl->lock);
                return ret;
        }
        
        read_unlock_bh(&tbl->lock);
        
        se = service_entry_create(alloc);
        
        if (!se)
                return -ENOMEM;

        ret = __service_entry_add_dev(se, dev, alloc);

        if (ret < 0) {
                service_entry_free(se);
        } else {
                write_lock_bh(&tbl->lock);
                se->node = bst_insert_prefix(&tbl->tree, &tbl->srv_ops, 
                                             se, srvid, prefix_size);
                write_unlock_bh(&tbl->lock);
                
                if (!se->node) {
                        service_entry_free(se);
                        ret = -ENOMEM;
                }
        }

        return ret;
}

int service_add(struct service_id *srvid, unsigned int prefix_size, 
                struct net_device *dev, gfp_t alloc)
{
        return service_table_add(&srvtable, srvid, prefix_size, dev, alloc);
}

void service_table_del(struct service_table *tbl, struct service_id *srvid, 
                       unsigned int prefix_size)
{
        write_lock_bh(&tbl->lock);
        bst_remove_prefix(&tbl->tree, srvid, prefix_size);
        write_unlock_bh(&tbl->lock);
}

void service_del(struct service_id *srvid, unsigned int prefix_size)
{
        return service_table_del(&srvtable, srvid, prefix_size);
}

static int del_dev_func(struct bst_node *n, void *arg)
{
        struct service_entry *se = get_service(n);
        char *devname = (char *)arg;
        int ret = 0, should_remove = 0;
        
        write_lock_bh(&se->devlock);
        
        ret = __service_entry_remove_dev(se, devname);

        if (ret == 1 && list_empty(&se->dev_list))
                should_remove = 1;

        write_unlock_bh(&se->devlock);

        if (should_remove)
                bst_node_remove(n);
        
        return ret;
}

static int service_table_del_dev(struct service_table *tbl, const char *devname)
{
        int ret = 0;

        write_lock_bh(&tbl->lock);
        if (tbl->tree.root)
                ret = bst_subtree_func(tbl->tree.root, del_dev_func, 
                                       (void *)devname);
        write_unlock_bh(&tbl->lock);

        return ret;
}

int service_del_dev(const char *devname)
{
        return service_table_del_dev(&srvtable, devname);
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
        tbl->srv_ops.print = service_entry_print;
        rwlock_init(&tbl->lock);
}

int __init service_init(void)
{
        service_table_init(&srvtable);
        return 0;
}

void __exit service_fini(void)
{
        service_table_destroy(&srvtable);
}
