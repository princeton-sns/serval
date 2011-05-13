/*
 * resolver_base.c
 *
 *  Created on: Feb 18, 2011
 *      Author: daveds
 */

#include "resolver_base.h"
#include <assert.h>
#include "debug.h"
#include "stdlib.h"
#include "unistd.h"

static void destroy_service_desc(void* value) {
    if(value == NULL) {
        return;
    }

    struct service_desc* sdesc = (struct service_desc*) value;
    free(sdesc);
}

static void destroy_net_addr(void* value) {
    if(value == NULL) {
        return;
    }

    struct net_addr* addr = (struct net_addr*) value;
    free(addr);
}

void create_base_resolver(struct sv_base_service_resolver *base) {
    assert(base);
    base->addresses = g_array_new(FALSE, TRUE, sizeof(struct net_addr));
    base->service_descs = g_ptr_array_new_with_free_func(destroy_service_desc);
}

int base_resolver_initialize(void* resolver) {
    assert(resolver);
    struct sv_base_service_resolver* base = (struct sv_base_service_resolver*) resolver;
    base->resolver.state = INITIALIZED;
    if(base->addresses == NULL) {
        base->addresses = g_array_new(FALSE, TRUE, sizeof(struct net_addr));
    }
    if(base->service_descs == NULL) {
        base->service_descs = g_ptr_array_new_with_free_func(destroy_service_desc);
    }
    return 0;
}

int base_resolver_finalize(void* resolver) {
    assert(resolver);

    struct sv_base_service_resolver* base = (struct sv_base_service_resolver*) resolver;

    if(base->addresses) {
        g_array_free(base->addresses, TRUE);
        base->addresses = NULL;
    }
    if(base->service_descs) {
        g_ptr_array_free(base->service_descs, TRUE);
        base->service_descs = NULL;
    }

    return 0;
}

void base_resolver_incref(void*resolver) {
    assert(resolver);
    struct sv_base_service_resolver* base = (struct sv_base_service_resolver*) resolver;
    atomic_inc(&base->resolver.ref_count);
}

struct net_addr* resolver_get_address(void* resolver, int index) {
    assert(resolver);

    struct sv_base_service_resolver* base = (struct sv_base_service_resolver*) resolver;
    if(index < 0 || index > base->addresses->len) {
        return NULL;
    }

return &g_array_index(base->addresses, struct net_addr, index);
}

void resolver_add_address(void* resolver, struct net_addr* addr) {
    assert(resolver);

    struct sv_base_service_resolver* base = (struct sv_base_service_resolver*) resolver;

    g_array_append_val(base->addresses, *addr);
}

static int resolver_find_address_index(struct sv_base_service_resolver* resolver,
        struct net_addr* addr) {
    int i = 0;
    for (; i < resolver->addresses->len; i++) {
        if(!memcmp(&g_array_index(resolver->addresses, struct net_addr, i), addr,
                        sizeof(struct net_addr))) {
            return i;
        }
    }
    return -1;
}

int resolver_remove_address(void* resolver, struct net_addr* addr) {
    assert(resolver);

    struct sv_base_service_resolver* base = (struct sv_base_service_resolver*) resolver;

    int index = resolver_find_address_index(base, addr);
    if(index >= 0) {
        g_array_remove_index(base->addresses, index);
    }
    return index;
}

int resolver_get_address_count(void* resolver) {
    assert(resolver);

    struct sv_base_service_resolver* base = (struct sv_base_service_resolver*) resolver;

    return base->addresses->len;
}
void resolver_clear_addresses(void* resolver) {
    assert(resolver);

    struct sv_base_service_resolver* base = (struct sv_base_service_resolver*) resolver;

    g_array_remove_range(base->addresses, 0, base->addresses->len);
}

struct service_desc* resolver_get_service_desc(void* resolver, int index) {
    assert(resolver);

    struct sv_base_service_resolver* base = (struct sv_base_service_resolver*) resolver;

    if(index < 0 || index >= base->service_descs->len) {
        return NULL;
    }

    return g_ptr_array_index(base->service_descs, index);
}

void resolver_add_service_desc(void* resolver, struct service_desc* sdesc) {
    assert(resolver);

    if(sdesc == NULL) {
        return;
    }
    /*TODO - check for dups? */
    struct sv_base_service_resolver* base = (struct sv_base_service_resolver*) resolver;

    g_ptr_array_add(base->service_descs, sdesc);
}

static int resolver_find_service_desc_index(struct sv_base_service_resolver* resolver,
        struct service_desc* service) {
    struct service_desc* desc;

    int i = 0;
    for (; i < resolver->service_descs->len; i++) {
        desc = g_ptr_array_index(resolver->service_descs, i);
        if(desc->prefix == service->prefix && !memcmp(&desc->service, &service->service,
                desc->prefix)) {
            return i;
        }
    }
    return -1;
}

int resolver_remove_service_desc(void* resolver, struct service_desc* sdesc) {
    assert(resolver);

    struct sv_base_service_resolver* base = (struct sv_base_service_resolver*) resolver;

    int index = resolver_find_service_desc_index(base, sdesc);
    if(index >= 0) {
        g_ptr_array_remove_index(base->service_descs, index);
    }

    return index;
}
int resolver_get_service_desc_count(void* resolver) {
    assert(resolver);

    struct sv_base_service_resolver* base = (struct sv_base_service_resolver*) resolver;

    return base->service_descs->len;
}
void resolver_clear_service_descs(void* resolver) {
    assert(resolver);

    struct sv_base_service_resolver* base = (struct sv_base_service_resolver*) resolver;

    g_ptr_array_remove_range(base->service_descs, 0, base->service_descs->len);
}

struct sv_service_resolver* resolver_incref(void* resolver) {
    assert(resolver);

    struct sv_base_service_resolver* base = (struct sv_base_service_resolver*) resolver;

    atomic_inc(&base->ref_count);

    return resolver;
}
int resolver_decref(void* resolver) {
    assert(resolver);

    struct sv_base_service_resolver* base = (struct sv_base_service_resolver*) resolver;

    int count = atomic_dec_return(&base->ref_count);

    if(count == 0) {
        /* free the resolver */
        free(resolver);
        return TRUE;
    }
    return FALSE;
}

void prep_stats_for_host(uint16_t type, void* host, void* net) {
    struct sv_instance_stats* istats = NULL;
    struct sv_instance_stats* ristats = NULL;

    struct sv_service_stats* sstats = NULL;
    struct sv_service_stats* rsstats = NULL;

    struct sv_table_stats* tstats = NULL;
    struct sv_table_stats* rtstats = NULL;

    struct sv_router_stats* rstats = NULL;
    struct sv_router_stats* rrstats = NULL;

    switch (type) {
    case SVS_INSTANCE_STATS:
        istats = (struct sv_instance_stats*) host;
        ristats = (struct sv_instance_stats*) net;

        memcpy(&istats->service, &ristats->service, sizeof(struct service_desc));
        istats->service.type = ntohs(ristats->service.type);
        memcpy(&istats->address, &ristats->address, sizeof(struct net_addr));
        istats->priority = ntohs(ristats->priority);
        istats->weight = ntohs(ristats->weight);
        istats->idle_timeout = ntohs(ristats->idle_timeout);
        istats->hard_timeout = ntohs(ristats->hard_timeout);
        istats->duration_sec = ntohl(ristats->duration_sec);
        istats->duration_nsec = ntohl(ristats->duration_nsec);
        istats->packets_resolved = ntohl(ristats->packets_resolved);
        istats->bytes_resolved = ntohl(ristats->bytes_resolved);
        istats->tokens_consumed = ntohl(ristats->tokens_consumed);
        break;
    case SVS_SERVICE_STATS:
        sstats = (struct sv_service_stats*) host;
        rsstats = (struct sv_service_stats*) net;

        memcpy(&sstats->service, &rsstats->service, sizeof(struct service_desc));
        sstats->service.type = ntohs(rsstats->service.type);
        sstats->bytes_dropped = ntohl(rsstats->bytes_dropped);
        sstats->packets_dropped = ntohl(rsstats->packets_dropped);
        sstats->instance_count = ntohl(rsstats->instance_count);
        sstats->duration_sec = ntohl(rsstats->duration_sec);
        sstats->duration_nsec = ntohl(rsstats->duration_nsec);
        sstats->packets_resolved = ntohl(rsstats->packets_resolved);
        sstats->bytes_resolved = ntohl(rsstats->bytes_resolved);
        sstats->tokens_consumed = ntohl(rsstats->tokens_consumed);
        break;

    case SVS_TABLE_STATS:
        tstats = (struct sv_table_stats*) host;
        rtstats = (struct sv_table_stats*) net;

        tstats->bytes_dropped = ntohl(rtstats->bytes_dropped);
        tstats->packets_dropped = ntohl(rtstats->packets_dropped);
        tstats->instance_count = ntohl(rtstats->instance_count);
        tstats->packets_resolved = ntohl(rtstats->packets_resolved);
        tstats->bytes_resolved = ntohl(rtstats->bytes_resolved);
        tstats->service_count = ntohl(rtstats->service_count);
        tstats->max_entries = ntohl(rtstats->max_entries);
        break;

    case SVS_ROUTER_STATS:
        rstats = (struct sv_router_stats*) host;
        rrstats = (struct sv_router_stats*) net;

        rstats->bytes_dropped = ntohl(rrstats->bytes_dropped);
        rstats->packets_dropped = ntohl(rrstats->packets_dropped);
        rstats->instance_count = ntohl(rrstats->instance_count);
        rstats->packets_resolved = ntohl(rrstats->packets_resolved);
        rstats->bytes_resolved = ntohl(rrstats->bytes_resolved);
        rstats->service_count = ntohl(rrstats->service_count);
        rstats->peers = ntohs(rrstats->peers);
        rstats->tables = ntohs(rrstats->tables);
        break;
        /* error! TODO */

    }

}

void prep_stats_for_network(uint16_t type, void* net, void* host) {

    struct sv_instance_stats* istats = NULL;
    struct sv_instance_stats* ristats = NULL;

    struct sv_service_stats* sstats = NULL;
    struct sv_service_stats* rsstats = NULL;

    struct sv_table_stats* tstats = NULL;
    struct sv_table_stats* rtstats = NULL;
    struct sv_router_stats* rstats = NULL;
    struct sv_router_stats* rrstats = NULL;

    switch (type) {
    case SVS_INSTANCE_STATS:
        istats = (struct sv_instance_stats*) net;
        ristats = (struct sv_instance_stats*) host;

        memcpy(&istats->service, &ristats->service, sizeof(struct service_desc));
        istats->service.type = htons(ristats->service.type);
        memcpy(&istats->address, &ristats->address, sizeof(struct net_addr));
        istats->priority = htons(ristats->priority);
        istats->weight = htons(ristats->weight);
        istats->idle_timeout = htons(ristats->idle_timeout);
        istats->hard_timeout = htons(ristats->hard_timeout);
        istats->duration_sec = htonl(ristats->duration_sec);
        istats->duration_nsec = htonl(ristats->duration_nsec);
        istats->packets_resolved = htonl(ristats->packets_resolved);
        istats->bytes_resolved = htonl(ristats->bytes_resolved);
        istats->tokens_consumed = htonl(ristats->tokens_consumed);
        break;
    case SVS_SERVICE_STATS:
        sstats = (struct sv_service_stats*) net;
        rsstats = (struct sv_service_stats*) host;

        memcpy(&sstats->service, &rsstats->service, sizeof(struct service_desc));
        sstats->service.type = htons(rsstats->service.type);
        sstats->bytes_dropped = htonl(rsstats->bytes_dropped);
        sstats->packets_dropped = htonl(rsstats->packets_dropped);
        sstats->instance_count = htonl(rsstats->instance_count);
        sstats->duration_sec = htonl(rsstats->duration_sec);
        sstats->duration_nsec = htonl(rsstats->duration_nsec);
        sstats->packets_resolved = htonl(rsstats->packets_resolved);
        sstats->bytes_resolved = htonl(rsstats->bytes_resolved);
        sstats->tokens_consumed = htonl(rsstats->tokens_consumed);
        break;

    case SVS_TABLE_STATS:
        tstats = (struct sv_table_stats*) net;
        rtstats = (struct sv_table_stats*) host;

        tstats->bytes_dropped = htonl(rtstats->bytes_dropped);
        tstats->packets_dropped = htonl(rtstats->packets_dropped);
        tstats->instance_count = htonl(rtstats->instance_count);
        tstats->packets_resolved = htonl(rtstats->packets_resolved);
        tstats->bytes_resolved = htonl(rtstats->bytes_resolved);
        tstats->service_count = htonl(rtstats->service_count);
        tstats->max_entries = htonl(rtstats->max_entries);
        break;

    case SVS_ROUTER_STATS:
        rstats = (struct sv_router_stats*) net;
        rrstats = (struct sv_router_stats*) host;

        rstats->bytes_dropped = htonl(rrstats->bytes_dropped);
        rstats->packets_dropped = htonl(rrstats->packets_dropped);
        rstats->instance_count = htonl(rrstats->instance_count);
        rstats->packets_resolved = htonl(rrstats->packets_resolved);
        rstats->bytes_resolved = htonl(rrstats->bytes_resolved);
        rstats->service_count = htonl(rrstats->service_count);
        rstats->peers = htons(rrstats->peers);
        rstats->tables = htons(rrstats->tables);
        break;
        /* error! TODO */

    }
}

