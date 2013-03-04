/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- 
 *
 * A hash table implementation with reference-counted elements.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#include <stdlib.h>
#include <pthread.h>
#include <common/hashtable.h>
#include <common/debug.h>

struct hashslot {
    struct hlist_head head;
	unsigned long     count;
	pthread_mutex_t   lock;
};

/*
  Hash table initialization.
*/
int hashtable_init(struct hashtable *table, 
                   unsigned int size)
{
    int i;

    memset(table, 0, sizeof(*table));
    table->hash = malloc(sizeof(struct hashslot) * size);

    if (!table->hash)
        return -1;
    
    table->mask = size - 1;
    atomic_set(&table->count, 0);

    /* LOG_DBG("Initializing hash table\n"); */

	for (i = 0; i <= table->mask; i++) {
		INIT_HLIST_HEAD(&table->hash[i].head);
		table->hash[i].count = 0;
		pthread_mutex_init(&table->hash[i].lock, NULL);
	}

    return 0;
}

void hashtable_fini(struct hashtable *table)
{
    int i;

    for (i = 0; i <= table->mask; i++) {
        struct hashelm *he;
        struct hlist_node *walk, *tmp;
        
        pthread_mutex_lock(&table->hash[i].lock);

        hlist_for_each_entry_safe(he, walk, tmp, 
                                  &table->hash[i].head, node) {
            hlist_del_init(&he->node);
            hashelm_put(he);
        }

		INIT_HLIST_HEAD(&table->hash[i].head);
		table->hash[i].count = 0;
        pthread_mutex_unlock(&table->hash[i].lock);
		pthread_mutex_destroy(&table->hash[i].lock);
	}
    atomic_set(&table->count, 0);
    free(table->hash);
}

int hashtable_for_each(struct hashtable *table, 
                       void (*action)(struct hashelm *, void *), 
                       void *data)
{
    int i, n = 0;

    if (!action)
        return -1;

    for (i = 0; i <= table->mask; i++) {
        struct hashelm *he;
        struct hlist_node *walk, *tmp;
        
        pthread_mutex_lock(&table->hash[i].lock);
        
        hlist_for_each_entry_safe(he, walk, tmp, 
                                  &table->hash[i].head, node) {
            action(he, data);
            n++;
        }
        pthread_mutex_unlock(&table->hash[i].lock);
	}
    return n;
}

unsigned int hashtable_count(struct hashtable *table)
{
    return atomic_read(&table->count);
}

static struct hashslot *get_slot(struct hashtable *tbl,
                                    unsigned int hash)
{
    return &tbl->hash[hash & tbl->mask];
}

int hashelm_hashed(struct hashelm *he)
{
    return !hlist_unhashed(&he->node);
}

int hashelm_hash(struct hashtable *table, struct hashelm *he, 
                 const void *key)
{
    struct hashslot *slot;

    if (!hlist_unhashed(&he->node)) {
        LOG_ERR("Hash element already hashed\n");
        return -1;
    }

    he->hash = he->hashfn(key);
    slot = get_slot(table, he->hash);
    
    pthread_mutex_lock(&slot->lock);
    slot->count++;
    atomic_inc(&table->count);
    hlist_add_head(&he->node, &slot->head);
    hashelm_hold(he);
    pthread_mutex_unlock(&slot->lock);

    return 0;
}

void hashelm_unhash(struct hashtable *table, struct hashelm *he)
{
    struct hashslot *slot;    

    slot = get_slot(table, he->hash);
    pthread_mutex_lock(&slot->lock);
    hlist_del_init(&he->node);
    slot->count--;
    atomic_dec(&table->count);
    hashelm_put(he);
    pthread_mutex_unlock(&slot->lock);
}

void __hashelm_unhash(struct hashtable *table, struct hashelm *he)
{
    struct hashslot *slot;    

    slot = get_slot(table, he->hash);
    hlist_del_init(&he->node);
    slot->count--;
    atomic_dec(&table->count);
    hashelm_put(he);
}

void hashelm_hold(struct hashelm *he)
{
    atomic_inc(&he->refcount);
}

void hashelm_put(struct hashelm *he)
{
    if (atomic_dec_and_test(&he->refcount)) 
        if (he->freefn) {
            he->freefn(he);
        }
}

int hashelm_init(struct hashelm *he,
                 hashfn_t hashfn, 
                 equalfn_t equalfn, 
                 freefn_t freefn)
{
    INIT_HLIST_NODE(&he->node);
    atomic_set(&he->refcount, 1);
    he->hashfn = hashfn;
    he->equalfn = equalfn;
    he->freefn = freefn;

    return 0;
}

struct hashelm *hashtable_lookup(struct hashtable *table, 
                                 const void *key, hashfn_t hashfn)
{
    struct hashelm *he;
    struct hlist_node *walk;
    struct hashslot *slot;

    slot = get_slot(table, hashfn(key));
    
    pthread_mutex_lock(&slot->lock);

    hlist_for_each_entry(he, walk, &slot->head, node) {
        if (he->equalfn(he, key)) {
            hashelm_hold(he);
            goto found;
        }
    }
    he = NULL;
found:
    pthread_mutex_unlock(&slot->lock);
    
    return he;
}
