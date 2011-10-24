/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * resolver.h
 *
 *  Created on: Feb 9, 2011
 *      Author: daveds
 */

#ifndef RESOLVER_H_
#define RESOLVER_H_

#include <netinet/serval.h>
#include "resolver_protocol.h"
/*
 * defines the resolver (peer, child, parent) abstract data type and
 * interface
 *
 */

#define DEFAULT_CAPACITY 1

typedef enum resolver_relation {
    RELATION_UNKNOWN = 0,
    RELATION_CHILD,
    RELATION_PEER,
    RELATION_PARENT,
    RELATION_SELF = 0xFFFF
} resolver_relation_t;

typedef enum resolver_state {
    CREATED = 0,
    INITIALIZED,
    DISCOVERED,
    ACTIVE,
    UNRESPONSIVE,
    DISAPPEARED,
    DESTROYED,
} resolver_state_t;

#define is_relation_known(rel) rel != RELATION_UNKNOWN;
#define is_relation_child(rel) rel == RELATION_CHILD;
#define is_relation_peer(rel) rel == RELATION_PEER;
#define is_relation_parent(rel) rel == RELATION_PARENT;
#define is_relation_self(rel) rel == RELATION_SELF;

//authoritative reg/unreg?
//discovery/hierarchy mechanisms?
typedef struct resolver_callback {
    void *target;
    void (*resolver_cb)(struct resolver_callback * cb,
                        int status, void *data);
} resolver_callback_t;

typedef struct stat_response {
    unsigned short type;
    unsigned short count;
    unsigned char *data;
} stat_response_t;

struct resolver_ops;

/* 
   Base resolver definition. This should be something we can pass
   accross networks.  */
struct resolver_stub {
    struct sockaddr_sv resolver_id;
    unsigned char state;
    long long last_access;
    uint32_t capabilities;
    uint32_t capacity;
    uint32_t relation;
};

typedef struct resolver {
    struct resolver_stub stub;
#define rsv_state stub.state
#define rsv_capabilities stub.capabilities
#define rsv_capacity stub.capacity
#define rsv_relation stub.relation
    const char *name;
    struct resolver_ops *ops;
} resolver_t;

/* this callback is necessary for informing associated objects
 * like the server_resolver that a peer is no longer valid for a given resolver
 */
typedef struct peer_status_callback {
    void *target;
    void (*peer_status_cb)(struct peer_status_callback * cb,
                           resolver_t *peer, 
                           enum resolver_state state);
} peer_status_callback_t;

typedef struct resolver_ops {
    int (*initialize)(resolver_t *resolver);
    int (*start)(resolver_t *resolver);
    void (*stop)(resolver_t *resolver);
    void (*finalize)(resolver_t *resolver);
    /* virtualized to call the right finalize... */
    void (*hold)(resolver_t *resolver);
    void (*put)(resolver_t *resolver);
    uint32_t(*get_uptime)(resolver_t *resolver);
    void (*set_uptime)(resolver_t *resolver, uint32_t uptime);

    void (*set_address)(resolver_t *resolver,
                        struct sockaddr *saddr, size_t len);
    void (*set_capabilities)(resolver_t *resolver,
                             uint32_t capabilities);
    /* get/set state? - locked? */
    resolver_t *(*get_peer)(resolver_t *resolver,
                            struct service_id *peer_id);
    int (*has_peer)(resolver_t *resolver, struct service_id *peer_id);
    int (*get_peer_count)(resolver_t *resolver);
    void (*clear_peers)(resolver_t *resolver);

    int (*peer_discovered)(resolver_t *resolver,
                           resolver_t *peer, uint16_t type);

    int (*peer_disappeared)(resolver_t *resolver,
                            resolver_t *peer, uint16_t type);

    //is there (should there be) any way to determine where the request has come from?
    //i.e. if it's from the resolution path, no down-call is needed to insert the resolution rule
    int (*register_services)(resolver_t *resolver,
                             resolver_t *peer,
                             const struct service_desc *services,
                             size_t num_svc, 
                             const struct net_addr *address,
                             uint32_t ttl);

    //zero signifies error, anything else is a xid
    int (*register_services_async)(resolver_t *resolver,
                                   resolver_t *peer,
                                   struct service_desc *services,
                                   size_t num_svc,
                                   struct net_addr *address,
                                   uint32_t ttl,
                                   resolver_callback_t *callback);
    int (*unregister_services)(resolver_t *resolver,
                               resolver_t *peer,
                               struct service_desc *services,
                               size_t num_svc, struct net_addr *address);
    int (*unregister_services_async)(resolver_t *resolver,
                                     resolver_t *peer,
                                     struct service_desc *services,
                                     size_t num_svc,
                                     struct net_addr *address,
                                     resolver_callback_t *callback);
    
    int (*query_services)(resolver_t *resolver,
                          resolver_t *peer,
                          struct service_desc *services, size_t num_svc);
    int (*query_services_async)(resolver_t *resolver,
                                resolver_t *peer,
                                struct service_desc *services,
                                size_t num_svc,
                                resolver_callback_t *callback);

    int (*update_services)(resolver_t *resolver,
                           resolver_t *peer, uint16_t type,
                           stat_response_t *responses);

    int (*get_service_updates)(resolver_t *resolver,
                               resolver_t *peer, uint16_t type,
                               struct service_desc *, size_t num_svc,
                               stat_response_t *responses);

    int (*get_service_updates_async)(resolver_t *resolver,
                                     resolver_t *peer,
                                     uint16_t type, struct service_desc *,
                                     size_t num_svc,
                                     stat_response_t *responses,
                                     resolver_callback_t *callback);

    //    int (*update_services_async)(resolver_t* resolver, uint16_t type, struct service_desc*,
    //            size_t num_svc, resolver_t_callback_t *callback);
    //
    //resolve multiple services?
    int (*resolve_service)(resolver_t *resolver,
                           resolver_t *peer,
                           struct service_desc *service,
                           struct net_addr *address);

    int (*resolve_service_async)(resolver_t *resolver,
                                 resolver_t *peer,
                                 struct service_desc *service,
                                 struct net_addr *address,
                                 resolver_callback_t *callback);

    int (*poke_resolver)(resolver_t *resolver,
                         resolver_t *peer, uint32_t count);
    int (*poke_resolver_async)(resolver_t *resolver,
                               resolver_t *peer, uint32_t count,
                               resolver_callback_t *callback);

} resolver_ops_t;

/* TODO - use some sort of iterator instead?
 * Effectively final functions (non-virtualizable)
 */

typedef enum resolver_type {
    RESOLVER_STACK,
    RESOLVER_REMOTE,
    RESOLVER_LOCAL,
} resolver_type_t;

resolver_t *resolver_create(resolver_type_t type); 
void resolver_free(resolver_t *resolver);
resolver_state_t resolver_get_state(resolver_t *resolver);
int resolver_register_service(resolver_t *resolver,
                              const struct service_id *srvid,
                              unsigned int prefix_bits,
                              const struct in_addr *ipaddr);
struct net_addr *resolver_get_address(resolver_t *resolver, int index);
int resolver_add_address(resolver_t *resolver, struct net_addr *addr);
int resolver_remove_address(resolver_t *resolver, struct net_addr *addr);
unsigned int resolver_get_address_count(resolver_t *resolver);
void resolver_clear_addresses(resolver_t *resolver);

struct service_desc *resolver_get_service_desc(resolver_t * resolver,
                                               int index);
int resolver_add_service_desc(resolver_t *resolver,
                              struct service_desc *sdesc);
int resolver_remove_service_desc(resolver_t *resolver,
                                 struct service_desc *sdesc);
unsigned int resolver_get_service_desc_count(resolver_t *resolver);
void resolver_clear_service_descs(resolver_t *resolver);

int resolver_register_peer_status_callback(resolver_t *resolver,
                                           peer_status_callback_t *cb);
int resolver_unregister_peer_status_callback(resolver_t *resolver,
                                             peer_status_callback_t *cb);
void prep_stats_for_host(uint16_t type, void *host, void *net);
void prep_stats_for_network(uint16_t type, void *net, void *host);

#endif /* RESOLVER_H_ */
