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

//authoritative reg/unreg?
//discovery/hierarchy mechanisms?
typedef struct sv_resolver_callback {
    void* target;
    void (*service_resolver_cb)(struct sv_resolver_callback* cb, int status, void* data);
} service_resolver_callback;

typedef struct sv_stat_response {
    uint16_t type;
    uint16_t count;
    uint8_t* data;
} stat_response;

struct sv_resolver_interface;

struct sv_service_resolver {
    struct sockaddr_sv resolver_id;
    enum resolver_state state;
    long long last_access;
    uint32_t capabilities;
    uint32_t capacity;
    uint32_t relation;
};

typedef struct {
    struct sv_service_resolver resolver;
    struct sv_resolver_interface* interface;
} service_resolver;

/* this callback is necessary for informing associated objects
 * like the server_resolver that a peer is no longer valid for a given resolver
 */
typedef struct sv_peer_status_callback {
    void* target;
    void (*peer_status_cb)(struct sv_peer_status_callback* cb, service_resolver* peer,
            enum resolver_state state);
} peer_status_callback;

struct sv_resolver_interface {
    int (*initialize)(service_resolver* resolver);
    void (*start)(service_resolver* resolver);
    void (*stop)(service_resolver* resolver);
    int (*finalize)(service_resolver* resolver);
    /* virtualized to call the right finalize...*/
    void (*incref)(service_resolver*resolver);
    void (*decref)(service_resolver*resolver);

    uint32_t (*get_uptime)(service_resolver* resolver);
    void (*set_uptime)(service_resolver* resolver, uint32_t uptime);

    void (*set_address)(service_resolver* resolver, struct sockaddr* saddr, size_t len);
    void (*set_capabilities)(service_resolver* resolver, uint32_t capabilities);
    /* get/set state? - locked? */
    service_resolver* (*get_peer)(service_resolver* resolver, struct service_id* peer_id);
    int (*has_peer)(service_resolver* resolver, struct service_id* peer_id);
    int (*get_peer_count)(service_resolver* resolver);
    void (*clear_peers)(service_resolver* resolver);

    int (*peer_discovered)(service_resolver* resolver, service_resolver* peer, uint16_t type);

    int (*peer_disappeared)(service_resolver* resolver, service_resolver* peer, uint16_t type);

    //is there (should there be) any way to determine where the request has come from?
    //i.e. if it's from the resolution path, no down-call is needed to insert the resolution rule
    int (*register_services)(service_resolver* resolver, service_resolver* peer,
            struct service_desc* services, size_t num_svc, struct net_addr* address, uint32_t ttl);

    //zero signifies error, anything else is a xid
    int (*register_services_async)(service_resolver* resolver, service_resolver* peer,
            struct service_desc* services, size_t num_svc, struct net_addr* address, uint32_t ttl,
            service_resolver_callback* callback);

    int (*unregister_services)(service_resolver* resolver, service_resolver* peer,
            struct service_desc* services, size_t num_svc, struct net_addr* address);
    int (*unregister_services_async)(service_resolver* resolver, service_resolver* peer,
            struct service_desc* services, size_t num_svc, struct net_addr* address,
            service_resolver_callback* callback);

    int
    (*query_services)(service_resolver* resolver, service_resolver* peer,
            struct service_desc* services, size_t num_svc);
    int (*query_services_async)(service_resolver* resolver, service_resolver* peer,
            struct service_desc* services, size_t num_svc, service_resolver_callback* callback);

    int (*update_services)(service_resolver* resolver, service_resolver* peer, uint16_t type,
            stat_response* responses);

    int (*get_service_updates)(service_resolver* resolver, service_resolver* peer, uint16_t type,
            struct service_desc*, size_t num_svc, stat_response* responses);

    int (*get_service_updates_async)(service_resolver* resolver, service_resolver* peer,
            uint16_t type, struct service_desc*, size_t num_svc, stat_response* responses,
            service_resolver_callback* callback);

    //    int (*update_services_async)(service_resolver* resolver, uint16_t type, struct service_desc*,
    //            size_t num_svc, service_resolver_callback* callback);
    //
    //resolve multiple services?
    int (*resolve_service)(service_resolver* resolver, service_resolver* peer,
            struct service_desc* service, struct net_addr* address);

    int (*resolve_service_async)(service_resolver* resolver, service_resolver* peer,
            struct service_desc* service, struct net_addr* address,
            service_resolver_callback* callback);

    int (*poke_resolver)(service_resolver* resolver, service_resolver* peer, uint32_t count);
    int (*poke_resolver_async)(service_resolver* resolver, service_resolver* peer, uint32_t count,
            service_resolver_callback* callback);

};

/* TODO - use some sort of iterator instead?
 * Effectively final functions (non-virtualizable)
 */
struct net_addr* resolver_get_address(service_resolver* resolver, int index);
void resolver_add_address(service_resolver* resolver, struct net_addr* addr);
int resolver_remove_address(service_resolver* resolver, struct net_addr* addr);
int resolver_get_address_count(service_resolver* resolver);
void resolver_clear_addresses(service_resolver* resolver);

struct service_desc* resolver_get_service_desc(service_resolver* resolver, int index);
void resolver_add_service_desc(service_resolver* resolver, struct service_desc* sdesc);
int resolver_remove_service_desc(service_resolver* resolver, struct service_desc* sdesc);
int resolver_get_service_desc_count(service_resolver* resolver);
void resolver_clear_service_descs(service_resolver* resolver);

void resolver_register_peer_status_callback(service_resolver* resolver, peer_status_callback* cb);
void resolver_unregister_peer_status_callback(service_resolver* resolver, peer_status_callback* cb);

//struct sv_service_resolver* resolver_incref(service_resolver* resolver);
//int resolver_decref(service_resolver* resolver);

void prep_stats_for_host(uint16_t type, void* host, void* net);
void prep_stats_for_network(uint16_t type, void* net, void* host);
#endif /* RESOLVER_H_ */
