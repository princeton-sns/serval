/*
 * resolver.c
 *
 *  Created on: Feb 13, 2011
 *      Author: daveds
 */

#include <assert.h>
#include "resolver.h"
#include "resolver_base.h"
#include "libstack/resolver_protocol.h"
#include "service_types.h"
#include "resolver_messaging.h"
#include "time_util.h"
#include "service_util.h"
#include "debug.h"

extern resolver_rpc* create_resolver_rpc(struct sockaddr_sv* local,
        struct sv_instance_addr* remote, uint16_t rpc_max_retry, uint16_t request_timeout,
        resolver_message_callback* cb);

struct sv_client_resolver {
    struct sv_base_service_resolver resolver;
    atomic_t request_xid;
    //rtt estimate? - proximity?
    uint32_t rtt_estimate;
    uint32_t uptime;
    task_mutex message_mutex;
    task_cond message_cond;
    resolver_rpc* messaging;
//resolver_message_callback callback;
};

struct query_response_barrier {
    struct message_barrier barrier;
    struct service_desc* services;
    int num_svc;
};

struct update_response_barrier {
    struct message_barrier barrier;
    stat_response* response;
    int limit;
};

struct resolution_response_barrier {
    struct message_barrier barrier;
    struct net_addr* address;
};

struct echo_response_barrier {
    struct message_barrier barrier;
    uint32_t count;
};

struct update_data {
    uint16_t type;
    uint16_t flags;
};

struct reg_data {
    struct net_addr* address;
    uint32_t ttl;
};

static int client_initialize(service_resolver* resolver);
static void client_stop(service_resolver* resolver);
static void client_start(service_resolver* resolver);

static int client_finalize(service_resolver* resolver);

//static message_channel* client_get_channel(service_resolver* resolver);
static void client_set_address(service_resolver* resolver, struct sockaddr* saddr, size_t len);

static int
        client_peer_discovered(service_resolver* resolver, service_resolver* peer, uint16_t type);
static int client_peer_disappeared(service_resolver* resolver, service_resolver* peer,
        uint16_t type);

static int client_register_services(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address, uint32_t ttl);
static int client_register_services_async(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address, uint32_t ttl,
        service_resolver_callback* callback);

static int client_unregister_services(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address);
static int client_unregister_services_async(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address,
        service_resolver_callback* callback);

static int client_query_services(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc);
static int client_query_services_async(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, service_resolver_callback* callback);

static int client_get_service_updates(service_resolver* resolver, service_resolver* peer,
        uint16_t type, struct service_desc*, size_t num_svc, stat_response* responses);
static int client_get_service_updates_async(service_resolver* resolver, service_resolver* peer,
        uint16_t type, struct service_desc*, size_t num_svc, stat_response* responses,
        service_resolver_callback* callback);

static int client_update_services(service_resolver* resolver, service_resolver* peer,
        uint16_t type, stat_response* responses);

static int client_resolve_service(service_resolver* resolver, service_resolver* peer,
        struct service_desc* service, struct net_addr* address);
static int
        client_resolve_service_async(service_resolver* resolver, service_resolver* peer,
                struct service_desc* service, struct net_addr* address,
                service_resolver_callback* callback);

static int client_poke_resolver(service_resolver* resolver, service_resolver* peer, uint32_t count);
static int client_poke_resolver_async(service_resolver* resolver, service_resolver* peer,
        uint32_t count, service_resolver_callback* callback);

static void client_incref(service_resolver* resolver);
static void client_decref(service_resolver* resolver);

static service_resolver* client_get_peer(service_resolver* resolver, struct service_id* peer_id) {
    return NULL;
}

static int client_has_peer(service_resolver* resolver, struct service_id* peer_id) {
    return FALSE;
}
static int client_get_peer_count(service_resolver* resolver) {
    return 0;
}

static void client_clear_peers(service_resolver* resolver) {

}

/* locking required? */
static uint32_t client_get_uptime(service_resolver* resolver) {
    assert(resolver);
    struct sv_client_resolver* cres = (struct sv_client_resolver*) resolver;
    return cres->uptime;
}

static void client_set_uptime(service_resolver* resolver, uint32_t uptime) {
    assert(resolver);
    struct sv_client_resolver* cres = (struct sv_client_resolver*) resolver;
    cres->uptime = uptime;
}

static struct sv_resolver_interface client_resolver_interface = {
//eh?
        .initialize = client_initialize,
        .start = client_start,
        .stop = client_stop,
        .finalize = client_finalize,
        .incref = client_incref,
        .decref = client_decref,
        .set_address = client_set_address,
        .set_capabilities = base_set_capabilities,
        .get_uptime = client_get_uptime,
        .set_uptime = client_set_uptime,
        .get_peer = client_get_peer,
        .has_peer = client_has_peer,
        .get_peer_count = client_get_peer_count,
        .clear_peers = client_clear_peers,
        .peer_discovered = client_peer_discovered,
        .peer_disappeared = client_peer_disappeared,
        .register_services = client_register_services,
        //zero signifies error, anything else is a xid
        .register_services_async = client_register_services_async,

        .unregister_services = client_unregister_services,
        .unregister_services_async = client_unregister_services_async,

        .query_services = client_query_services,
        .query_services_async = client_query_services_async,

        .update_services = client_update_services,

        .get_service_updates = client_get_service_updates,
        .get_service_updates_async = client_get_service_updates_async,
        //resolve multiple services?
        .resolve_service = client_resolve_service,
        .resolve_service_async = client_resolve_service_async,

        .poke_resolver = client_poke_resolver,
        .poke_resolver_async = client_poke_resolver_async };

static struct service_desc* find_service_desc_eq(struct service_desc* services, int num_svcs,
        struct service_desc* service);

static int client_send_resolver_requests(struct sv_client_resolver* clientres, uint8_t type,
        uint16_t max_services, size_t msize, void(*init_request)(struct sv_control_header* message,
                void* data), void* data, struct service_desc* services, size_t num_svc,
        struct message_barrier* barrier, resolver_message_callback* callback, int should_wait);

static void client_trigger_default_callback(struct message_barrier* barrier) {
    assert(barrier);
    if(barrier->callback) {
        service_resolver_callback* cb = (service_resolver_callback*) barrier->callback;
        cb->service_resolver_cb(cb, -barrier->status, NULL);
    }
}

static void client_resolver_handle_success_echo(struct message_barrier* barrier, const void* msg,
        size_t len) {
    struct sv_echo_message* message = (struct sv_echo_message*) msg;
    struct echo_response_barrier* ebarrier = (struct echo_response_barrier*) ebarrier;

    if(ebarrier->count != ntohl(message->count)) {
        ebarrier->barrier.status = SV_ERR_INVALID_ECHO_COUNT;
    }

    /* estimate RTT - TODO */
}
static struct service_desc* find_service_desc_eq(struct service_desc* services, int num_svcs,
        struct service_desc* service);

static void client_resolver_handle_success_query(struct message_barrier* barrier, const void* msg,
        size_t len) {
    struct sv_control_header* message = (struct sv_control_header*) msg;

    struct query_response_barrier* qbarrier = (struct query_response_barrier*) barrier;

    /* adjust the values - find the right service desc */
    struct sv_query_response* response = (struct sv_query_response*) message;
    int num_svcs = NUM_SERVICES(message, sizeof(struct sv_query_response));
    struct service_desc* service = NULL;
    int i = 0;
    for(; i < num_svcs; i++) {

        service = find_service_desc_eq(qbarrier->services, qbarrier->num_svc,
                &response->service_ids[i]);

        if(service == NULL) {
            continue;
        }

        service->type = ntohs(response->service_ids[i].type);
        service->flags = response->service_ids[i].flags;
        service->prefix = response->service_ids[i].prefix;
    }
}

static void client_trigger_query_callback(struct message_barrier* barrier) {
    assert(barrier);
    if(barrier->callback) {
        service_resolver_callback* cb = (service_resolver_callback*) barrier->callback;
        struct query_response_barrier* qbarrier = (struct query_response_barrier*) barrier;
        cb->service_resolver_cb(cb, qbarrier->num_svc, qbarrier->services);
    }
}

static void client_resolver_handle_success_resolution(struct message_barrier* barrier,
        const void* msg, size_t len) {
    struct sv_control_header* message = (struct sv_control_header*) msg;

    struct resolution_response_barrier* rbarrier = (struct resolution_response_barrier*) barrier;

    /* adjust the values - find the right service desc */
    struct sv_resolution_response* response = (struct sv_resolution_response*) message;
    /* todo - sanity check the service id? */
    memcpy(&rbarrier->address, &response->address, sizeof(struct net_addr));
}

static void client_trigger_resolution_callback(struct message_barrier* barrier) {
    assert(barrier);
    if(barrier->callback) {
        service_resolver_callback* cb = (service_resolver_callback*) barrier->callback;
        struct resolution_response_barrier* rbarrier =
                (struct resolution_response_barrier*) barrier;
        cb->service_resolver_cb(cb, -barrier->status, &rbarrier->address);
    }
}

static void client_resolver_handle_success_update(struct message_barrier* barrier, const void*msg,
        size_t len) {
    struct sv_control_header* message = (struct sv_control_header*) msg;

    struct update_response_barrier* ubarrier = (struct update_response_barrier*) barrier;

    /* append the stats */
    struct sv_update_message* update = (struct sv_update_message*) message;

    /* sanity check the type? */
    if(ubarrier->response->type != ntohs(update->type)) {
        /*error TODO */
    }

    int statsize = get_stat_size(ubarrier->response->type);

    int statcount = (len - sizeof(struct sv_update_message)) / statsize;

    int over = statcount - ubarrier->limit + ubarrier->response->count;

    if(over > 0) {
        over += 10;
        /*expand by 10*/
        if(ubarrier->response->data) {
            ubarrier->response->data = (uint8_t*) realloc(ubarrier->response->data,
                    (ubarrier->response->count + over) * statsize);
        } else {
            ubarrier->response->data = (uint8_t*) malloc((ubarrier->response->count + over)
                    * statsize);
        }

        if(ubarrier->response->data == NULL) {
            LOG_ERR("Could not allocate stat response data for %i", (ubarrier->response->count + over) * statsize);
            return;
        }

        ubarrier->limit += over;
        bzero(ubarrier->response->data + (ubarrier->response->count * statsize), over * statsize);

    }
    int i = 0;
    for(; i < statcount; i++) {
        prep_stats_for_host(ubarrier->response->type, ubarrier->response->data
                + (ubarrier->response->count * statsize), update->body + statsize * i);

        ubarrier->response->count++;
    }

}

static void client_trigger_update_callback(struct message_barrier* barrier) {
    assert(barrier);
    if(barrier->callback) {
        service_resolver_callback* cb = (service_resolver_callback*) barrier->callback;
        struct update_response_barrier* ubarrier = (struct update_response_barrier*) barrier;
        cb->service_resolver_cb(cb, barrier->successes, &ubarrier->response);
    }
}

static void resolver_message_default_cb(resolver_message_callback* cb, uint16_t type,
        struct sv_control_header* message, size_t len, struct sv_instance_addr* remote) {
    assert(cb);
    struct message_barrier* barrier = (struct message_barrier*) cb->target;

    ((struct sv_client_resolver*) barrier->private)->resolver.resolver.resolver.last_access
            = get_current_time_ms();

    message_barrier_default_cb(barrier, type, message, len);
}

static void init_register_request(struct sv_control_header* message, void* data) {
    struct sv_register_message* rmessage = (struct sv_register_message*) message;
    struct reg_data* rdata = (struct reg_data*) data;
    memcpy(&rmessage->address, rdata->address, sizeof(struct net_addr));
    rdata->ttl = htonl(rdata->ttl);
}

static void init_noop(struct sv_control_header* message, void* data) {

}

static void init_unregister_request(struct sv_control_header* message, void* data) {
    struct sv_unregister_message* rmessage = (struct sv_unregister_message*) message;
    struct reg_data* rdata = (struct reg_data*) data;
    memcpy(&rmessage->address, rdata->address, sizeof(struct net_addr));

}
static void init_update_request(struct sv_control_header* message, void* data) {
    struct sv_update_message* rmessage = (struct sv_update_message*) message;
    struct update_data* udata = (struct update_data*) data;
    rmessage->type = htons(udata->type);
    rmessage->flags = htons(udata->flags);
}

service_resolver* create_client_service_resolver(struct sockaddr_sv* local,
        struct sv_instance_addr* remote, uint32_t uptime, uint32_t capabilities, uint32_t capacity,
        uint8_t relation) {
    struct sv_client_resolver* clientres = (struct sv_client_resolver*) malloc(sizeof(*clientres));

    if(clientres == NULL) {
        LOG_ERR("Could not allocate memory for client service resolver");
        return NULL;
    }

    bzero(clientres, sizeof(*clientres));

    init_base_resolver(&clientres->resolver);

    memcpy(&clientres->resolver.resolver.resolver.resolver_id, &remote->service,
            sizeof(struct sockaddr_sv));

    /*first address specified */
    clientres->uptime = uptime;
    clientres->resolver.resolver.resolver.capabilities = capabilities;
    clientres->resolver.resolver.resolver.capacity = capacity;
    clientres->resolver.resolver.resolver.relation = relation;

    if(!(clientres->messaging = create_resolver_rpc(local, remote, RPC_MAX_RETRY,
            CLIENT_REQUEST_TIMEOUT, NULL))) {
        return NULL;
    }

    clientres->resolver.resolver.interface = &client_resolver_interface;

    return &clientres->resolver.resolver;
}

static int client_initialize(service_resolver* resolver) {
    assert(resolver);
    struct sv_client_resolver* clientres = (struct sv_client_resolver*) resolver;

    int retval = base_resolver_initialize(resolver);
    if(retval) {
        return retval;
    }
    task_mutex_init(&clientres->message_mutex);
    task_cond_init(&clientres->message_cond);

    retval = clientres->messaging->interface->initialize(clientres->messaging);
    return retval;
}

static void client_start(service_resolver* resolver) {
    assert(resolver);
    if(resolver->resolver.state < INITIALIZED) {
        return;
    }
    struct sv_client_resolver* clientres = (struct sv_client_resolver*) resolver;
    clientres->messaging->interface->start(clientres->messaging);

    resolver->resolver.state = ACTIVE;
}

static void client_stop(service_resolver* resolver) {
    assert(resolver);
    if(resolver->resolver.state < ACTIVE) {
        return;
    }

    struct sv_client_resolver* clientres = (struct sv_client_resolver*) resolver;
    clientres->messaging->interface->stop(clientres->messaging);
    resolver->resolver.state = DISCOVERED;
}

static int client_finalize(service_resolver* resolver) {
    assert(resolver);

    struct sv_client_resolver* clientres = (struct sv_client_resolver*) resolver;

    int retval = base_resolver_finalize(resolver);
    task_mutex_destroy(&clientres->message_mutex);
    task_cond_destroy(&clientres->message_cond);

    if(clientres->messaging) {
        retval = clientres->messaging->interface->finalize(clientres->messaging);
        free(clientres->messaging);
        clientres->messaging = NULL;
    }
    return retval;

}

static void client_incref(service_resolver* resolver) {
    assert(resolver);
    base_resolver_incref(resolver);

}
static void client_decref(service_resolver* resolver) {
    assert(resolver);
    struct sv_client_resolver* clientres = (struct sv_client_resolver*) resolver;

    if(atomic_dec_and_test(&clientres->resolver.ref_count)) {
        resolver->interface->finalize(resolver);
        free(resolver);
    }
}

static void client_set_address(service_resolver* resolver, struct sockaddr* saddr, size_t len) {
    assert(resolver);
    struct sv_client_resolver* clientres = (struct sv_client_resolver*) resolver;
    clientres->messaging->resolver.channel->interface->set_peer_address(
            clientres->messaging->resolver.channel, saddr, len);
    base_resolver_set_address(resolver, saddr, len);
}

resolver_rpc* client_get_messaging(service_resolver* resolver) {
    assert(resolver);
    struct sv_client_resolver* clientres = (struct sv_client_resolver*) resolver;
    return clientres->messaging;
}

static int client_peer_discovered(service_resolver* resolver, service_resolver* peer,
        uint16_t flags) {
    assert(resolver);
    struct sv_client_resolver* clientres = (struct sv_client_resolver*) resolver;

    struct sv_discover_message * dmessage = NULL;

    /* packetize services into requests */
    int retval = 0;

    /* lock the peer for accessing service_desc? TODO */
    int count = resolver_get_service_desc_count(peer);

    /* TODO lots of mem copying here of service descriptions - would be nice to use io vecs*/
    int len = sizeof(*dmessage) + count * sizeof(struct service_desc);
    dmessage = (struct sv_discover_message*) malloc(len);

    if(dmessage == NULL) {
        LOG_ERR("Could not allocate discover message of size: %i", len);
        return -1;
    }

    bzero(dmessage, sizeof(*dmessage));

    uint32_t xid = atomic_add_return(1, &clientres->request_xid);
    init_control_header(&dmessage->header, SV_DISCOVER_MESSAGE, xid, len);

    /* accessor functions? */
    dmessage->flags = htons(flags);
    dmessage->capabilities = htonl(peer->resolver.capabilities);
    dmessage->capacity = htonl(peer->resolver.capacity);
    dmessage->uptime = htonl(peer->interface->get_uptime(peer));

    LOG_DBG("Sending discovery message with %i service descs to remote resolver(%s): %s\n",count, service_id_to_str(&clientres->resolver.resolver.resolver.resolver_id.sv_srvid), print_control_message(&dmessage->header, len));
    /* to inform the receiving peer to ignore the SID/addr values in the discover message
     * and use the src values instead
     */
    dmessage->resolver_id.flags = SVSF_INVALID;

    /*type may need htons...*/
    struct service_desc* sdesc;
    int i = 0;
    for(; i < count; i++) {
        sdesc = resolver_get_service_desc(peer, i);
        memcpy(&dmessage->service_prefixes[i], sdesc, sizeof(*sdesc));
        dmessage->service_prefixes[i].type = htons(sdesc->type);
    }

    /* no direct response expected - the server-handler will take care of the incoming discovery message */
    retval = clientres->messaging->interface->send_resolver_message(clientres->messaging, xid,
            &dmessage->header, sizeof(*dmessage), NULL);

    return retval;
}

static int client_peer_disappeared(service_resolver* resolver, service_resolver* peer,
        uint16_t flags) {
    assert(resolver);
    struct sv_client_resolver* clientres = (struct sv_client_resolver*) resolver;

    struct sv_disappear_message* dmessage = NULL;

    /* packetize services into requests */
    int retval = 0;

    /* TODO lots of mem copying here...*/
    dmessage = (struct sv_disappear_message*) malloc(sizeof(*dmessage));

    if(dmessage == NULL) {
        LOG_ERR("Could not allocate disappear message");
        return -1;
    }

    bzero(dmessage, sizeof(*dmessage));

    uint32_t xid = atomic_add_return(1, &clientres->request_xid);
    init_control_header(&dmessage->header, SV_DISAPPEAR_MESSAGE, xid, sizeof(*dmessage));

    dmessage->flags = htons(flags);
    dmessage->resolver_id.flags = SVSF_INVALID;

    retval = clientres->messaging->interface->send_resolver_message(clientres->messaging, xid,
            &dmessage->header, sizeof(*dmessage), NULL);

    return retval;
}

static struct service_desc* find_service_desc_eq(struct service_desc* services, int num_svcs,
        struct service_desc* service) {
    /* full service id byte match */
    int i = 0;
    for(; i < num_svcs; i++) {
        if(memcmp(&services[i].service, &service->service, sizeof(struct service_id)) == 0) {
            return &services[i];
        }
    }

    return NULL;
}

static int _client_register_services(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address, uint32_t ttl,
        service_resolver_callback* cb) {
    assert(resolver);

    struct sv_client_resolver* clientres = (struct sv_client_resolver*) resolver;

    /* packetize services into requests */
    uint16_t max_services =
            (resolver_rpc_get_max_message_size((resolver_rpc*) clientres->messaging)
                    - sizeof(struct sv_register_message)) / sizeof(struct service_desc);

    resolver_message_callback* callback;
    struct message_barrier* barrier;
    struct message_barrier sbarrier;

    if(cb) {
        barrier = (struct message_barrier*) malloc(sizeof(*barrier));

    } else {
        barrier = &sbarrier;
    }

    bzero(barrier, sizeof(*barrier));

    init_message_barrier(barrier, clientres, SV_ACK, message_barrier_handle_success_default,
            message_barrier_handle_failure_default, client_trigger_default_callback);
    barrier->callback = cb;
    barrier->private = clientres;

    if(cb) {
        callback = (resolver_message_callback*) malloc(sizeof(*callback));
        barrier->linger_data = callback;
    } else {
        resolver_message_callback scallback;
        callback = &scallback;
    }

    callback->target = barrier;
    callback->resolver_message_cb = resolver_message_default_cb;

    struct reg_data rdata;
    rdata.address = address;
    rdata.ttl = ttl;

    return client_send_resolver_requests(clientres, SV_REGISTER_REQUEST, max_services,
            sizeof(struct sv_register_message), init_register_request, &rdata, services, num_svc,
            barrier, callback, cb == NULL);
}

static int client_register_services(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address, uint32_t ttl) {

    return _client_register_services(resolver, peer, services, num_svc, address, ttl, NULL);
}

static int client_register_services_async(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address, uint32_t ttl,
        service_resolver_callback* callback) {

    return _client_register_services(resolver, peer, services, num_svc, address, ttl, callback);
}

static int client_send_resolver_requests(struct sv_client_resolver* clientres, uint8_t type,
        uint16_t max_services, size_t msize, void(*init_request)(struct sv_control_header* message,
                void* data), void* data, struct service_desc* services, size_t num_svc,
        struct message_barrier* barrier, resolver_message_callback* callback, int should_wait) {

    /* construct the message - note that ownership is passed on downstream*/
    struct sv_control_header* message = NULL;

    /* packetize services into requests */
    /* fire off all messages in parallel - with window limit? TODO */
    uint16_t len = 0;
    int index = 0;
    int limit = 0;
    int retval = 0;

    struct service_desc* service_ids;
    int count;
    while(num_svc > 0) {
        limit = (num_svc < max_services ? num_svc : max_services);
        len = msize + limit * sizeof(struct service_desc);
        /* this would probably do much better with a scatter/gather interface */
        message = (struct sv_control_header*) malloc(len);

        if(message == NULL) {
            LOG_ERR("Could not allocate message of size: %i", len);
            return -1;
        }

        bzero(message, len);
        uint32_t xid = atomic_add_return(1, &clientres->request_xid);
        init_control_header(message, type, xid, len);

        init_request(message, data);

        service_ids = (struct service_desc*) (((uint8_t*) message) + msize);
        int i = 0;
        for(; i < +limit; i++) {
            memcpy(&service_ids[i], &services[index + i], sizeof(struct service_desc));
            service_ids[i].type = htons(services[index + 1].type);
        }

        index += limit;
        num_svc -= limit;

        atomic_inc(&barrier->message_count);
        while((retval = clientres->messaging->interface->send_resolver_message(
                clientres->messaging, xid, message, len, callback)) < 0) {

            /* request window congested - currently async calls will block indefinitely here... TODO */
            if(retval == -2) {

                count = atomic_read(&barrier->message_count);

                task_mutex_lock(&clientres->message_mutex);
                while(atomic_read(&barrier->message_count) == count) {
                    task_cond_wait(&clientres->message_cond, &clientres->message_mutex);
                }
                task_mutex_unlock(&clientres->message_mutex);
            } else {
                /* real error TODO*/
                break;
            }
        }
    }

    /* synchronous call so wait for everything to reply */
    if(should_wait) {
        wait_for_message_barrier(barrier);
    }

    return barrier->successes;
}

static int _client_unregister_services(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address,
        service_resolver_callback* cb) {
    assert(resolver);
    struct sv_client_resolver* clientres = (struct sv_client_resolver*) resolver;

    /* packetize services into requests */
    uint16_t max_services =
            (resolver_rpc_get_max_message_size((resolver_rpc*) clientres->messaging)
                    - sizeof(struct sv_unregister_message)) / sizeof(struct service_desc);

    struct message_barrier* barrier;
    resolver_message_callback* callback;
    struct message_barrier sbarrier;

    if(cb) {
        barrier = (struct message_barrier*) malloc(sizeof(*barrier));

    } else {
        barrier = &sbarrier;
    }

    bzero(barrier, sizeof(*barrier));

    init_message_barrier(barrier, clientres, SV_ACK, message_barrier_handle_success_default,
            message_barrier_handle_failure_default, client_trigger_default_callback);
    barrier->callback = cb;
    barrier->private = clientres;

    if(cb) {
        callback = (resolver_message_callback*) malloc(sizeof(*callback));
        barrier->linger_data = callback;
    } else {
        resolver_message_callback scallback;
        callback = &scallback;
    }

    callback->target = barrier;
    callback->resolver_message_cb = resolver_message_default_cb;

    struct reg_data rdata;
    rdata.address = address;

    return client_send_resolver_requests(clientres, SV_UNREGISTER_REQUEST, max_services,
            sizeof(struct sv_unregister_message), init_unregister_request, &rdata, services,
            num_svc, barrier, callback, cb == NULL);

}

static int client_unregister_services(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address) {
    return _client_unregister_services(resolver, peer, services, num_svc, address, NULL);
}

static int client_unregister_services_async(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address,
        service_resolver_callback* callback) {
    return _client_unregister_services(resolver, peer, services, num_svc, address, callback);
}

static int _client_query_services(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, service_resolver_callback* cb) {
    assert(resolver);
    struct sv_client_resolver* clientres = (struct sv_client_resolver*) resolver;

    /* packetize services into requests */
    uint16_t max_services =
            (resolver_rpc_get_max_message_size((resolver_rpc*) clientres->messaging)
                    - sizeof(struct sv_query_request)) / sizeof(struct service_desc);

    struct query_response_barrier* qbarrier;
    resolver_message_callback* callback;
    struct query_response_barrier sbarrier;

    if(cb) {
        qbarrier = (struct query_response_barrier*) malloc(sizeof(*qbarrier));

    } else {
        qbarrier = &sbarrier;
    }

    bzero(qbarrier, sizeof(*qbarrier));

    init_message_barrier(&qbarrier->barrier, clientres, SV_QUERY_REPLY,
            client_resolver_handle_success_query, message_barrier_handle_failure_default,
            client_trigger_query_callback);

    qbarrier->barrier.callback = cb;

    /* it would be safer to allocate memory for the services and free it after triggering the callback */
    qbarrier->services = services;
    qbarrier->num_svc = num_svc;
    qbarrier->barrier.private = clientres;

    if(cb) {
        callback = (resolver_message_callback*) malloc(sizeof(*callback));
        qbarrier->barrier.linger_data = callback;
    } else {
        resolver_message_callback scallback;
        callback = &scallback;
    }

    callback->target = qbarrier;
    callback->resolver_message_cb = resolver_message_default_cb;

    return client_send_resolver_requests(clientres, SV_QUERY_REQUEST, max_services,
            sizeof(struct sv_query_request), init_noop, NULL, services, num_svc,
            &qbarrier->barrier, callback, cb == NULL);
}

static int client_query_services(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc) {
    return _client_query_services(resolver, peer, services, num_svc, NULL);
}

static int client_query_services_async(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, service_resolver_callback* callback) {
    return _client_query_services(resolver, peer, services, num_svc, callback);
}

static int _client_get_service_updates(service_resolver* resolver, service_resolver* peer,
        uint16_t type, struct service_desc* services, size_t num_svc, stat_response* responses,
        service_resolver_callback* cb) {
    assert(resolver);
    struct sv_client_resolver* clientres = (struct sv_client_resolver*) resolver;

    /* packetize services into requests */
    uint16_t max_services =
            (resolver_rpc_get_max_message_size((resolver_rpc*) clientres->messaging)
                    - sizeof(struct sv_update_request)) / sizeof(struct service_desc);

    struct update_response_barrier* ubarrier;
    resolver_message_callback * callback;
    struct update_response_barrier sbarrier;

    if(cb) {
        ubarrier = (struct update_response_barrier*) malloc(sizeof(*ubarrier));

    } else {
        ubarrier = &sbarrier;
    }

    bzero(ubarrier, sizeof(*ubarrier));

    init_message_barrier(&ubarrier->barrier, clientres, SV_UPDATE_MESSAGE,
            client_resolver_handle_success_update, message_barrier_handle_failure_default,
            client_trigger_update_callback);

    ubarrier->barrier.callback = cb;
    ubarrier->barrier.private = clientres;

    if(responses) {
        ubarrier->response = responses;
        ubarrier->limit = responses->count;
        responses->count = 0;
    }

    if(cb) {
        callback = (resolver_message_callback*) malloc(sizeof(*callback));
        ubarrier->barrier.linger_data = callback;
    } else {
        resolver_message_callback scallback;
        callback = &scallback;
    }

    callback->target = ubarrier;
    callback->resolver_message_cb = resolver_message_default_cb;

    struct update_data udata;
    udata.type = type;
    udata.flags = 0;

    return client_send_resolver_requests(clientres, SV_UPDATE_REQUEST, max_services,
            sizeof(struct sv_update_request), init_update_request, &udata, services, num_svc,
            &ubarrier->barrier, callback, cb == NULL);

}

static int client_get_service_updates_async(service_resolver* resolver, service_resolver* peer,
        uint16_t type, struct service_desc* services, size_t num_svc, stat_response* responses,
        service_resolver_callback* callback) {
    return _client_get_service_updates(resolver, peer, type, services, num_svc, responses, callback);
}

static int client_get_service_updates(service_resolver* resolver, service_resolver* peer,
        uint16_t type, struct service_desc* services, size_t num_svc, stat_response* responses) {
    return _client_get_service_updates(resolver, peer, type, services, num_svc, responses, NULL);
}

static int client_update_services(service_resolver* resolver, service_resolver* peer,
        uint16_t type, stat_response* responses) {
    assert(resolver);

    struct sv_client_resolver* clientres = (struct sv_client_resolver*) resolver;

    struct sv_update_message* umessage = NULL;

    /* packetize services into requests */
    /* fire off all messages in parallel - with window limit? TODO */
    uint16_t len = 0;
    int index = 0;
    int limit = 0;
    int retval = 0;

    int statsize = get_stat_size(type);

    //int statcount = (len - sizeof(struct sv_update_message)) / statsize;

    uint16_t max_responses = (resolver_rpc_get_max_message_size(
            (resolver_rpc*) clientres->messaging) - sizeof(struct sv_update_message)) / statsize;

    uint16_t count = responses->count;
    while(count > 0) {

        limit = (count < max_responses ? count : max_responses);
        len = sizeof(*umessage) + limit * statsize;
        /* this would probably do much better with a scatter/gather interface */
        umessage = (struct sv_update_message*) malloc(len);

        if(umessage == NULL) {
            /* TODO */
            return -1;
        }

        bzero(umessage, len);

        uint32_t xid = atomic_add_return(1, &clientres->request_xid);
        init_control_header(&umessage->header, SV_UPDATE_MESSAGE, xid, len);

        umessage->flags = 0;
        umessage->type = htons(type);
        int i = 0;
        for(; i < limit; i++) {
            prep_stats_for_network(type, umessage->body + (index + i) * statsize, responses->data
                    + statsize * (index + i));
        }

        index += limit;
        count -= limit;

        /*unwindowed? TODO*/
        while((retval = clientres->messaging->interface->send_resolver_message(
                clientres->messaging, xid, &umessage->header, len, NULL)) < 0) {

            /* request window congested TODO */
            if(retval == -2) {

            } else {
                /* real error TODO*/
                break;
            }
        }
    }

    return 1;
}

//resolver multiple services?
static int _client_resolve_service(service_resolver* resolver, service_resolver* peer,
        struct service_desc* service, struct net_addr* address, service_resolver_callback* cb) {
    assert(resolver);
    struct sv_client_resolver* clientres = (struct sv_client_resolver*) resolver;

    struct sv_resolution_request * rmessage = NULL;

    /* packetize services into requests */
    /* fire off all messages in parallel - with window limit? TODO */
    int retval = 0;

    struct resolution_response_barrier* rbarrier;
    resolver_message_callback * callback;
    struct resolution_response_barrier sbarrier;

    if(cb) {
        rbarrier = (struct resolution_response_barrier*) malloc(sizeof(*rbarrier));

    } else {
        rbarrier = &sbarrier;
    }

    bzero(rbarrier, sizeof(*rbarrier));

    init_message_barrier(&rbarrier->barrier, clientres, SV_RESOLUTION_REPLY,
            client_resolver_handle_success_resolution, message_barrier_handle_failure_default,
            client_trigger_resolution_callback);

    rbarrier->barrier.callback = cb;
    rbarrier->address = address;
    rbarrier->barrier.private = clientres;

    if(cb) {
        callback = (resolver_message_callback*) malloc(sizeof(*callback));
        rbarrier->barrier.linger_data = callback;
    } else {
        resolver_message_callback scallback;
        callback = &scallback;
    }

    callback->target = rbarrier;
    callback->resolver_message_cb = resolver_message_default_cb;

    rmessage = (struct sv_resolution_request*) malloc(sizeof(*rmessage));

    if(rmessage == NULL) {
        LOG_ERR("Could not allocate message resolution message");
        if(cb) {
            free(rbarrier);
            free(callback);
        }
        return -1;
    }

    bzero(rmessage, sizeof(*rmessage));
    uint32_t xid = atomic_add_return(1, &clientres->request_xid);
    init_control_header(&rmessage->header, SV_RESOLUTION_REQUEST, xid, sizeof(*rmessage));

    memcpy(&rmessage->service_id, service, sizeof(*service));
    rmessage->service_id.type = htons(service->type);

    atomic_inc(&rbarrier->barrier.message_count);
    retval = clientres->messaging->interface->send_resolver_message(clientres->messaging, xid,
            &rmessage->header, sizeof(*rmessage), callback);

    /* synchronous call so wait for everything to reply */
    if(cb == NULL) {
        wait_for_message_barrier(&rbarrier->barrier);
    }

    return rbarrier->barrier.successes;

}

static int client_resolve_service(service_resolver* resolver, service_resolver* peer,
        struct service_desc* service, struct net_addr* address) {
    return _client_resolve_service(resolver, peer, service, address, NULL);
}

static int client_resolve_service_async(service_resolver* resolver, service_resolver* peer,
        struct service_desc* service, struct net_addr* address, service_resolver_callback* callback) {
    return _client_resolve_service(resolver, peer, service, address, callback);
}

static int _client_poke_resolver(service_resolver* resolver, service_resolver* peer,
        uint32_t count, service_resolver_callback* cb) {
    assert(resolver);
    struct sv_client_resolver* clientres = (struct sv_client_resolver*) resolver;

    struct sv_echo_message * emessage = NULL;

    /* packetize services into requests */
    /* fire off all messages in parallel - with window limit? TODO */
    int retval = 0;

    struct echo_response_barrier* ebarrier;
    struct echo_response_barrier barrier;

    resolver_message_callback * callback;

    if(cb) {
        ebarrier = (struct echo_response_barrier*) malloc(sizeof(*ebarrier));

    } else {
        ebarrier = &barrier;
    }

    bzero(ebarrier, sizeof(*ebarrier));

    init_message_barrier(&ebarrier->barrier, clientres, SV_ECHO_REPLY,
            client_resolver_handle_success_echo, message_barrier_handle_failure_default,
            client_trigger_default_callback);

    ebarrier->count = count;
    ebarrier->barrier.private = clientres;

    if(cb) {
        callback = (resolver_message_callback*) malloc(sizeof(*callback));
        ebarrier->barrier.linger_data = callback;
    } else {
        resolver_message_callback scallback;
        callback = &scallback;
    }

    callback->target = ebarrier;
    callback->resolver_message_cb = resolver_message_default_cb;

    emessage = (struct sv_echo_message*) malloc(sizeof(*emessage));

    if(emessage == NULL) {
        LOG_ERR("Could not allocate echo message");
        return -1;
    }

    bzero(emessage, sizeof(*emessage));

    uint32_t xid = atomic_add_return(1, &clientres->request_xid);
    init_control_header(&emessage->header, SV_ECHO_REQUEST, xid, sizeof(*emessage));

    emessage->count = htonl(count);
    emessage->timestamp = (uint32_t) get_current_time_ms();

    retval = clientres->messaging->interface->send_resolver_message(clientres->messaging, xid,
            &emessage->header, sizeof(*emessage), callback);

    if(cb == NULL) {
        wait_for_message_barrier(&ebarrier->barrier);
    }

    return barrier.barrier.successes;
}

static int client_poke_resolver(service_resolver* resolver, service_resolver* peer, uint32_t count) {
    return _client_poke_resolver(resolver, peer, count, NULL);
}

static int client_poke_resolver_async(service_resolver* resolver, service_resolver* peer,
        uint32_t count, service_resolver_callback* cb) {
    return _client_poke_resolver(resolver, peer, count, cb);
}
