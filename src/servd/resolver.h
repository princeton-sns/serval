/*
 * resolver.h
 *
 *  Created on: Feb 9, 2011
 *      Author: daveds
 */

#ifndef RESOLVER_H_
#define RESOLVER_H_

#include <netinet/serval.h>
#include "serval/atomic.h"
#include "libstack/resolver_protocol.h"
/*
 * defines the resolver (peer, child, parent) abstract data type and interface
 *
 */

#define DEFAULT_CAPACITY 1

enum resolver_relation {
    RELATION_UNKNOWN = 0,
    RELATION_CHILD = 1,
    RELATION_PEER = 2,
    RELATION_PARENT = 3,
    RELATION_SELF = 0xFFFF
};

enum resolver_state {
    CREATED = 0,
    INITIALIZED = 1,
    DISCOVERED = 2,
    ACTIVE = 3,
    UNRESPONSIVE = 4,
    DISAPPEARED = 5,
    DESTROYED = 6
};

#define is_relation_known(rel) rel != RELATION_UNKNOWN;
#define is_relation_child(rel) rel == RELATION_CHILD;
#define is_relation_peer(rel) rel == RELATION_PEER;
#define is_relation_parent(rel) rel == RELATION_PARENT;
#define is_relation_self(rel) rel == RELATION_SELF;

//make this an opaque blob?
struct sv_service_resolver {
    struct sockaddr_sv resolver_id;
    //node or index?

    uint64_t last_access;
    uint32_t capabilities; //reference openflow? (transit, terminal, authoritative,specialized)
    uint32_t capacity; //(table size in K?, req/s, etc)

    atomic_t ref_count;
    //with interfaces? multiple addresses reachable through the same interface?
    uint16_t relation;
    uint16_t state;
};

//authoritative reg/unreg?
//discovery/hierarchy mechanisms?
typedef struct sv_callback {
    void* target;
    void (*service_resolver_cb)(void* target, int status, void* data);
} service_resolver_callback;

typedef struct sv_stat_response {
    uint16_t type;
    uint16_t count;
    uint8_t* data;
} stat_response;

struct sv_resolver_interface;

typedef struct sv_resolver {
    void* target;
    struct sv_resolver_interface* interface;
} service_resolver;

struct sv_resolver_interface {
    int (*initialize)(void* resolver);
    void (*start)(void* resolver);
    void (*stop)(void* resolver);
    int (*finalize)(void* resolver);
    /* virtualized to call the right finalize...*/
    void (*incref)(void*resolver);
    void (*decref)(void*resolver);

    uint32_t (*get_uptime)(void* resolver);
    void (*set_uptime)(void* resolver, uint32_t uptime);

    /* get/set state? - locked? */
    service_resolver* (*get_peer)(void* resolver, struct service_id* peer_id);
    int (*has_peer)(void* resolver, struct service_id* peer_id);
    int (*get_peer_count)(void* resolver);

    int (*peer_discovered)(void* resolver, service_resolver* peer, uint16_t type);

    int (*peer_disappeared)(void* resolver, service_resolver* peer, uint16_t type);

    //is there (should there be) any way to determine where the request has come from?
    //i.e. if it's from the resolution path, no down-call is needed to insert the resolution rule
    int (*register_services)(void* resolver, service_resolver* peer, struct service_desc* services,
            size_t num_svc, struct net_addr* address, uint32_t ttl);

    //zero signifies error, anything else is a xid
    int (*register_services_async)(void* resolver, service_resolver* peer,
            struct service_desc* services, size_t num_svc, struct net_addr* address, uint32_t ttl,
            service_resolver_callback* callback);

    int (*unregister_services)(void* resolver, service_resolver* peer,
            struct service_desc* services, size_t num_svc, struct net_addr* address);
    int (*unregister_services_async)(void* resolver, service_resolver* peer,
            struct service_desc* services, size_t num_svc, struct net_addr* address,
            service_resolver_callback* callback);

    int
    (*query_services)(void* resolver, service_resolver* peer, struct service_desc* services,
            size_t num_svc);
    int (*query_services_async)(void* resolver, service_resolver* peer,
            struct service_desc* services, size_t num_svc, service_resolver_callback* callback);

    int (*update_services)(void* resolver, service_resolver* peer, uint16_t type,
            stat_response* responses);

    int (*get_service_updates)(void* resolver, service_resolver* peer, uint16_t type,
            struct service_desc*, size_t num_svc, stat_response* responses);

    int (*get_service_updates_async)(void* resolver, service_resolver* peer, uint16_t type,
            struct service_desc*, size_t num_svc, stat_response* responses,
            service_resolver_callback* callback);

    //    int (*update_services_async)(void* resolver, uint16_t type, struct service_desc*,
    //            size_t num_svc, service_resolver_callback* callback);
    //
    //resolve multiple services?
    int (*resolve_service)(void* resolver, service_resolver* peer, struct service_desc* service,
            struct net_addr* address);

    int (*resolve_service_async)(void* resolver, service_resolver* peer,
            struct service_desc* service, struct net_addr* address,
            service_resolver_callback* callback);

    int (*poke_resolver)(void* resolver, service_resolver* peer, uint32_t count);
    int (*poke_resolver_async)(void* resolver, service_resolver* peer, uint32_t count,
            service_resolver_callback* callback);

};

/* TODO - use some sort of iterator instead?
 * Effectively final functions (non-virtualizable)
 */
struct net_addr* resolver_get_address(void* resolver, int index);
void resolver_add_address(void* resolver, struct net_addr* addr);
int resolver_remove_address(void* resolver, struct net_addr* addr);
int resolver_get_address_count(void* resolver);
void resolver_clear_addresses(void* resolver);

struct service_desc* resolver_get_service_desc(void* resolver, int index);
void resolver_add_service_desc(void* resolver, struct service_desc* sdesc);
int resolver_remove_service_desc(void* resolver, struct service_desc* sdesc);
int resolver_get_service_desc_count(void* resolver);
void resolver_clear_service_descs(void* resolver);

struct sv_service_resolver* resolver_incref(void* resolver);
int resolver_decref(void* resolver);

void prep_stats_for_host(uint16_t type, void* host, void* net);
void prep_stats_for_network(uint16_t type, void* net, void* host);
#endif /* RESOLVER_H_ */
