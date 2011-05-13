/*
 * resolver_base.h
 *
 *  Created on: Feb 18, 2011
 *      Author: daveds
 */

#ifndef RESOLVER_BASE_H_
#define RESOLVER_BASE_H_

#include <glib.h>
#include "serval/atomic.h"
#include "resolver.h"

struct sv_base_service_resolver {
    struct sv_service_resolver resolver;
    atomic_t ref_count;
    GArray* addresses;
    GPtrArray* service_descs;
};

int base_resolver_initialize(void* resolver);
int base_resolver_finalize(void* resolver);
void base_resolver_incref(void*resolver);
void create_base_resolver(struct sv_base_service_resolver *base);

void
        init_control_header(struct sv_control_header* header, uint8_t type, uint32_t xid,
                uint16_t len);

static inline int get_stat_size(uint16_t type) {
    switch(type) {
        case SVS_INSTANCE_STATS:
            return sizeof(struct sv_instance_stats);
        case SVS_SERVICE_STATS:
            return sizeof(struct sv_service_stats);
        case SVS_TABLE_STATS:
            return sizeof(struct sv_table_stats);
        case SVS_ROUTER_STATS:
            return sizeof(struct sv_router_stats);
        default:
            return 0;
    }
}

#endif /* RESOLVER_BASE_H_ */
