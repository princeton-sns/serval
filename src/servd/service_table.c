/*
 * service_table.c
 *
 *  Created on: Mar 3, 2011
 *      Author: daveds
 */

#include "service_table.h"
#include "debug.h"
#include "prefixtrie.h"
#include "cmwc.h"
#include <assert.h>
#include <glib.h>

#define SERVICE_FILL_FACTOR 0.5
#define SERVICE_KEY_LEN 256

struct ref_list {
    struct list_head head;
    uint32_t priority;
    uint32_t normalizer;
    uint32_t count;
};

struct ref_entry {
    struct list_head head;
    struct service_reference* ref;
};

/* TODO for large scale replciated services, iterating over a list may be really slow*/
static inline struct ref_entry* find_reference_in_list(struct ref_list* rlist,
        struct service_id* sid, struct net_addr* address) {
    struct ref_entry* entry;
    list_for_each_entry(entry, &rlist->head, head) {
        if(memcmp(entry->ref->instance.service.sv_srvid.srv_un.un_id8, sid->srv_un.un_id8, 32) == 0
                && memcmp(&entry->ref->instance.address.sin.sin_addr, &address->net_un.un_ip,
                        sizeof(struct in_addr)) == 0) {
            return entry;
        }
    }
    return NULL;
}

static inline int find_priority_index(GPtrArray* pri_array, uint32_t priority) {
    assert(pri_array);
    if(pri_array->len == 0) {
        return -1;
    }

    struct ref_list* rlist = NULL;

    /*binary search*/
    int lower = 0;
    int upper = pri_array->len;
    int index = pri_array->len / 2;

    while(index < upper) {
        rlist = (struct ref_list*) g_ptr_array_index(pri_array, index);

        if(rlist->priority < priority) {
            upper = index;
            index = lower + (index - lower) / 2;
        } else if(rlist->priority > priority) {
            lower = index + 1;
            index = lower + (upper - lower) / 2;
        } else {
            return index;
        }
    }
    /*TODO - return -(index + 1)? - g_ptr_array does not support arbitrary insertion*/
    return -1;
}

int service_table_initialize(struct sv_service_table* st) {
    assert(st);
    return prefix_trie_initialize(&st->service_trie, SERVICE_KEY_LEN, SERVICE_FILL_FACTOR);
}

int service_table_finalize(struct sv_service_table* st) {
    /* remove all elements */
    assert(st);

    struct service_table_iter iter;

    service_table_iter_init(&iter, st);

    while(service_table_iter_next(&iter, NULL)) {
        service_table_iter_remove(&iter, NULL);
    }

    service_table_iter_destroy(&iter);
    return prefix_trie_finalize(&st->service_trie);
}

void service_table_iter_init(struct service_table_iter* iter, struct sv_service_table* st) {
    prefix_trie_iter_init(&iter->trie_iter, &st->service_trie);
    iter->cur_entry = NULL;
    iter->cur_list = NULL;
    iter->pri_array = NULL;
    iter->cur_index = 0;

    iter->next_entry = NULL;

    iter->table = st;

    //    if(prefix_trie_iter_next(&iter->trie_iter, NULL, NULL, (void**) &iter->pri_array)) {
    //        assert(iter->pri_array);
    //        assert(iter->pri_array->len > 0);
    //        iter->cur_list = (struct ref_list*) g_ptr_array_index(iter->pri_array, iter->cur_index);
    //        assert(iter->cur_list);
    //        assert(!list_empty(&iter->cur_list->head));
    //        iter->cur_entry = list_entry(iter->cur_list->head.next, struct ref_entry, head);
    //    }
}

int service_table_iter_next(struct service_table_iter* iter, struct service_reference** sref) {
    assert(iter);

    if(iter->next_entry) {
        /*last one returned*/
        if(iter->next_entry == &iter->cur_list->head) {
            /*end of the list*/
            iter->cur_entry = NULL;
            iter->next_entry = NULL;
            iter->cur_list = NULL;
        } else {
            goto out;
        }
    }

    if(iter->pri_array) {
        if(iter->cur_index < iter->pri_array->len - 1) {
            iter->cur_list
                    = (struct ref_list*) g_ptr_array_index(iter->pri_array, ++iter->cur_index);
            assert(iter->cur_list);
            assert(!list_empty(&iter->cur_list->head));

            iter->next_entry = iter->cur_list->head.next;
            goto out;
        } else {
            iter->pri_array = NULL;
            iter->cur_index = 0;
        }
    }

    if(prefix_trie_iter_next(&iter->trie_iter, NULL, NULL, (void**) &iter->pri_array)) {
        assert(iter->pri_array);
        assert(iter->pri_array->len > 0);
        iter->cur_list = (struct ref_list*) g_ptr_array_index(iter->pri_array, iter->cur_index);
        assert(iter->cur_list);
        assert(!list_empty(&iter->cur_list->head));
        iter->next_entry = iter->cur_list->head.next;
    }

    out: if(iter->next_entry) {
        iter->cur_entry = (struct ref_entry*) iter->next_entry;
        iter->next_entry = iter->cur_entry->head.next;

        if(sref) {
            *sref = iter->cur_entry->ref;
        }
        return TRUE;
    }

    return FALSE;
}
void service_table_iter_destroy(struct service_table_iter* iter) {
    assert(iter);
    prefix_trie_iter_destroy(&iter->trie_iter);
}

size_t service_table_iter_reference_count(struct service_table_iter* iter) {
    assert(iter);
    /*reference count the last ref returned*/
    size_t count = 0;
    //    if(!iter->last_entry) {
    //        /*cannot obtain reference count on a removed reference*/
    //        return -1;
    //    }
    if(iter->pri_array) {
        int i = 0;
        for(; i < iter->pri_array->len; i++) {
            count += ((struct ref_list*) g_ptr_array_index(iter->pri_array, i))->count;
        }
    }
    return count;
}

/* removes the reference most recently returned by a call to service_table_iter_next
 * the entire reference is freed
 */
void service_table_iter_remove(struct service_table_iter* iter, struct service_reference** sref) {
    assert(iter);

    if(iter->cur_entry) {
        /*entry returned on prev call*/
        if(sref) {
            *sref = iter->cur_entry->ref;
        } else {
            free(iter->cur_entry->ref);
        }

        list_del(&iter->cur_entry->head);

        free(iter->cur_entry);
        iter->cur_entry = NULL;

        iter->table->count--;
        iter->cur_list->count--;

        if(list_empty(&iter->cur_list->head)) {
            iter->next_entry = NULL;

            assert(iter->cur_list->count == 0);
            g_ptr_array_remove_index(iter->pri_array, iter->cur_index);
            free(iter->cur_list);
            iter->cur_list = NULL;

            if(iter->pri_array->len == 0) {
                assert(iter->cur_index == 0);
                prefix_trie_iter_remove(&iter->trie_iter);
                g_ptr_array_free(iter->pri_array, TRUE);
                iter->pri_array = NULL;
                iter->cur_index = 0;
            }
        }

    }
}

size_t service_table_size(struct sv_service_table* st) {
    return st->count;
}

static int priority_comparison(const void* d1, const void* d2) {
    if(d1 == d2) {
        return 0;
    }

    struct ref_list* rlist1 = (struct ref_list*) d1;
    struct ref_list* rlist2 = (struct ref_list*) d2;

    if(rlist1->priority < rlist2->priority) {
        return 1;
    }
    if(rlist1->priority > rlist2->priority) {
        return -1;
    }

    return 0;

}

int service_table_add_service_reference(struct sv_service_table* st, struct service_reference* sref) {
    assert(st);
    assert(sref);

    /*TODO may be more efficient using a conditional insert*/
    GPtrArray* pri_array = (GPtrArray*) prefix_trie_find(&st->service_trie,
            sref->instance.service.sv_srvid.srv_un.un_id8, sref->instance.service.sv_prefix_bits);

    if(pri_array == NULL) {
        pri_array = g_ptr_array_new();
        prefix_trie_insert(&st->service_trie, sref->instance.service.sv_srvid.srv_un.un_id8,
                sref->instance.service.sv_prefix_bits, pri_array);
    }

    int index = find_priority_index(pri_array, sref->priority);
    struct ref_list* rlist = NULL;
    if(index < 0) {
        rlist = (struct ref_list*) malloc(sizeof(*rlist));
        bzero(rlist, sizeof(*rlist));
        INIT_LIST_HEAD(&rlist->head);
        rlist->priority = sref->priority;
        g_ptr_array_add(pri_array, rlist);
        g_ptr_array_sort(pri_array, priority_comparison);
    } else {
        rlist = (struct ref_list*) g_ptr_array_index(pri_array, index);
    }

    /*sanity check to make sure the reference does not exist*/

    if(find_reference_in_list(rlist, &sref->instance.service.sv_srvid,
            (struct net_addr*) &sref->instance.address.sin.sin_addr) != NULL) {
        LOG_DBG("Service reference already exists in the table: %s @ %i\n", service_id_to_str(
                        &sref->instance.service.sv_srvid), sref->instance.address.sin.sin_addr.s_addr);
        return -1;
    }
    struct ref_entry* rentry = (struct ref_entry*) malloc(sizeof(*rentry));
    bzero(rentry, sizeof(*rentry));
    rentry->ref = sref;

    list_add_tail(&rentry->head, &rlist->head);
    rlist->count++;
    /*sanity check the range*/
    /*TODO - for RR or DRR, linked list is best, for sampling, a re-normalized sorted array would be better*/
    rlist->normalizer += sref->weight;
    st->count++;

    /*TODO might be better to cache this count value*/
    int count = 0;
    int i = 0;
    for(; i < pri_array->len; i++) {
        count += ((struct ref_list*) g_ptr_array_index(pri_array, i))->count;
    }
    return count;
}

int service_table_remove_service_reference(struct sv_service_table* st, uint8_t flags,
        uint8_t prefix, struct service_id* sid, struct net_addr* address,
        struct service_reference** sref) {
    assert(st);
    assert(sid);
    assert(address);

    GPtrArray* pri_array = (GPtrArray*) prefix_trie_find(&st->service_trie, sid->srv_un.un_id8,
            prefix);

    if(pri_array == NULL) {
        return -1;
    }

    //    int index = find_priority_index(pri_array, priority);
    //    if(index < 0) {
    //        return -1;
    //    }
    //    struct ref_list* rlist = (struct ref_list*) g_ptr_array_index(pri_array, index);
    //    struct ref_entry* rentry = find_reference_in_list(rlist, sid, address);


    struct ref_list* rlist = NULL;
    struct ref_entry* rentry = NULL;
    int i = 0;
    /* TODO without a priority, this could be a painful search */
    for(; i < pri_array->len; i++) {
        rlist = (struct ref_list*) g_ptr_array_index(pri_array, i);

        /*sanity check to make sure the reference does not exist*/
        rentry = find_reference_in_list(rlist, sid, address);

        if(rentry != NULL) {

            break;
        }
    }

    if(rentry == NULL) {
        return -1;
    }

    list_del(&rentry->head);
    rlist->normalizer -= rentry->ref->weight;

    /*the service table owns the reference - delete it!*/
    assert(rentry->ref);

    if(sref == NULL) {
        free(rentry->ref);
    } else {
        *sref = rentry->ref;
    }

    free(rentry);
    rlist->count--;

    if(rlist->count == 0) {
        assert(list_empty(&rlist->head));
        g_ptr_array_remove_index(pri_array, i);

        free(rlist);

        if(pri_array->len == 0) {
            assert(i == 0);
            prefix_trie_remove(&st->service_trie, sid->srv_un.un_id8, prefix);
            g_ptr_array_free(pri_array, TRUE);
            pri_array = NULL;
        }
    }

    st->count--;

    if(pri_array == NULL) {
        return 0;
    }

    int count = 0;
    i = 0;
    for(; i < pri_array->len; i++) {
        count += ((struct ref_list*) g_ptr_array_index(pri_array, i))->count;
    }

    return count;
}

struct service_reference* service_table_find_service_reference(struct sv_service_table* st,
        uint8_t flags, uint8_t prefix, struct service_id* sid, struct net_addr* address) {

    assert(st);

    GPtrArray* pri_array = (GPtrArray*) prefix_trie_find(&st->service_trie, sid->srv_un.un_id8,
            prefix);

    if(pri_array == NULL) {
        return NULL;
    }

    struct ref_list* rlist = NULL;
    struct ref_entry* rentry = NULL;
    int i = 0;
    /* TODO without a priority, this could be a painful search */
    for(; i < pri_array->len; i++) {
        rlist = (struct ref_list*) g_ptr_array_index(pri_array, i);

        /*sanity check to make sure the reference does not exist*/
        rentry = find_reference_in_list(rlist, sid, address);

        if(rentry != NULL) {

            return rentry->ref;
        }
    }

    return NULL;
}

int service_table_find_service_references(struct sv_service_table* st, uint8_t flags,
        uint8_t prefix, struct service_id* sid, struct service_reference*** sref, size_t* cnt) {
    assert(st);
    assert(sref);
    assert(cnt);

    GPtrArray* pri_array = (GPtrArray*) prefix_trie_find(&st->service_trie, sid->srv_un.un_id8,
            prefix);

    if(pri_array == NULL) {
        *cnt = 0;
        *sref = NULL;
        return 0;
    }

    /*first determine the array to allocate*/
    int count = 0;
    int i = 0;
    struct ref_entry* entry;
    struct ref_list* rlist;
    for(; i < pri_array->len; i++) {
        rlist = (struct ref_list*) g_ptr_array_index(pri_array, i);
        count += rlist->count;
    }

    struct service_reference** srefs = (struct service_reference**) malloc(sizeof(*srefs) * count);

    int index = 0;
    for(i = 0; i < pri_array->len; i++) {
        rlist = (struct ref_list*) g_ptr_array_index(pri_array, i);

        list_for_each_entry(entry, &rlist->head, head) {
            srefs[index++] = entry->ref;
        }
    }

    *sref = srefs;
    *cnt = count;
    return 0;
}

struct service_reference* service_table_resolve_service(struct sv_service_table* st, uint8_t flags,
        uint8_t prefix, struct service_id* sid) {
    assert(st);

    GPtrArray* pri_array = (GPtrArray*) prefix_trie_find(&st->service_trie, sid->srv_un.un_id8,
            prefix);

    if(pri_array == NULL) {
        return NULL;
    }

    struct ref_entry* entry;
    /*first entry is highest prioriy */
    struct ref_list* rlist = g_ptr_array_index(pri_array, 0);

    uint32_t range = 0;
    uint32_t sample = (uint32_t) ((cmwc4096() / MAX_NUM) * rlist->normalizer);

    list_for_each_entry(entry, &rlist->head, head) {
        range += entry->ref->weight;
        if(range >= sample) {
            return entry->ref;

        }
    }

    /*should not get here*/
    return entry->ref;
}

int service_table_update_service_stats(struct sv_service_table* st, struct sv_service_stats* sstat) {
    return 0;
}
int service_table_get_table_stats(struct sv_service_table* st, struct sv_table_stats* tstat) {
    /*not implemented yet*/
    return 0;
}

void print_service_table(FILE* fptr, struct sv_service_table* table) {
    assert(table);

    struct service_table_iter iter;
    bzero(&iter, sizeof(iter));
    service_table_iter_init(&iter, table);
    fprintf(fptr, "%-64s %-6s %-18s %-10s %-10s %-10s\n", "prefix", "bits", "address", "priority",
            "weight", "ttl");

    char buffer[128];
    struct service_reference* ref;
    int bytes = 0;
    int i = 0;
    int len = 0;
    while(service_table_iter_next(&iter, &ref)) {
        bytes = ref->instance.service.sv_prefix_bits / 8 + (ref->instance.service.sv_prefix_bits
                % 8 == 0 ? 0 : 1);
        for(i = 0; i < bytes; i++) {
            len += snprintf(&buffer[i * 2], 128 - len, "%02x",
                    ref->instance.service.sv_srvid.srv_un.un_id8[i] & 0xff);

        }

        fprintf(fptr, "%-64s %-6i %-18s %-10i %-10i %-10i\n", buffer,
                ref->instance.service.sv_prefix_bits,
                inet_ntoa(ref->instance.address.sin.sin_addr), ref->priority, ref->weight, ref->ttl);
    }

    service_table_iter_destroy(&iter);
}

