/*
 * service_table.h
 *
 *  Created on: Feb 9, 2011
 *      Author: daveds
 */

#ifndef SERVICE_TABLE_H_
#define SERVICE_TABLE_H_

#include "service_types.h"
#include "libstack/resolver_protocol.h"
#include "libserval/serval.h"
#include "prefixtrie.h"

#include <glib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
struct ref_entry;
struct ref_list;

/* implement the table as a 3-level trie of tries for the 96 bit prefix and then a hashtable for the remaining key bits
 * alternatively, a full prefix-matching table would use an 8 level trie
 * */
struct sv_service_table {
    struct prefix_trie_struct service_trie;
    uint32_t count;
    struct sv_table_stats table_stats;
};

struct service_table_iter {
    struct prefix_trie_iter trie_iter;
    int cur_index;
    GPtrArray* pri_array;
    struct ref_entry* cur_entry;
    struct ref_list* cur_list;

    struct list_head* next_entry;

    struct sv_service_table* table;
};

void service_table_iter_init(struct service_table_iter* iter, struct sv_service_table* st);
int service_table_iter_next(struct service_table_iter* iter, struct service_reference** sref);
size_t service_table_iter_reference_count(struct service_table_iter* iter);
void service_table_iter_remove(struct service_table_iter* iter, struct service_reference** sref);
void service_table_iter_destroy(struct service_table_iter* iter);

size_t service_table_size(struct sv_service_table* st);

int service_table_initialize(struct sv_service_table* st);
int service_table_finalize(struct sv_service_table* st);

int
service_table_add_service_reference(struct sv_service_table* st, struct service_reference* sref);

int service_table_remove_service_reference(struct sv_service_table* st, uint8_t flags,
        uint8_t prefix, struct service_id* sid, struct net_addr* address,
        struct service_reference** sref);

struct service_reference* service_table_find_service_reference(struct sv_service_table* st,
        uint8_t flags, uint8_t prefix, struct service_id* sid, struct net_addr* address);

/*caller is responsible for deallocating sref memory*/
int
service_table_find_service_references(struct sv_service_table* st, uint8_t flags, uint8_t prefix,
        struct service_id* sid, struct service_reference*** sref, size_t* count);

struct service_reference* service_table_resolve_service(struct sv_service_table* st, uint8_t flags,
        uint8_t prefix, struct service_id* sid);

int service_table_get_table_stats(struct sv_service_table* st, struct sv_table_stats* tstat);
int service_table_update_service_stats(struct sv_service_table* st, struct sv_service_stats* sstat);

void print_service_table(FILE* fptr, struct sv_service_table* table);
#endif /* SERVICE_TABLE_H_ */
