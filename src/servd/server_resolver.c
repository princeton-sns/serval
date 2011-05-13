/*
 * server_resolver.c
 *
 *  Created on: Feb 23, 2011
 *      Author: daveds
 */

#include "server_resolver.h"
#include "time_util.h"
#include "task.h"
#include "debug.h"

#include <assert.h>

extern int create_client_service_resolver(struct sockaddr_sv* local,
        struct sv_instance_addr* remote, uint32_t uptime, uint32_t capabilities, uint32_t capacity,
        uint8_t relation, service_resolver* resolver);

extern int create_resolver_rpc(struct sockaddr_sv* local, struct sv_instance_addr* remote,
        uint16_t rpc_max_retry, uint16_t request_timeout, resolver_message_callback* cb,
        resolver_rpc* messaging);

static void server_resolver_message_cb(void* target, uint16_t type,
        struct sv_control_header* message, size_t len, struct sv_instance_addr* remote);
static int callback_info_initialize(struct callback_info* cinfo);
static int callback_info_finalize(struct callback_info* cinfo);
static void destroy_cb_info(void* data);

struct server_rpc_handler* create_server_rpc_handler(service_resolver* res) {
    if(res == NULL || res->target == NULL) {
        return NULL;
    }
    struct server_rpc_handler* handler = (struct server_rpc_handler*) malloc(sizeof(*handler));
    if(init_server_rpc_handler(handler, res)) {
        free(handler);
        return NULL;
    }
    return handler;
}
int init_server_rpc_handler(struct server_rpc_handler* handler, service_resolver* res) {
    bzero(handler, sizeof(*handler));
    handler->resolver = *res;

    handler->def_callback.handler = handler;

    handler->callback.target = &handler->def_callback;
    handler->callback.resolver_message_cb = server_resolver_message_cb;

    struct sv_instance_addr defaddr;
    bzero(&defaddr, sizeof(defaddr));

    memcpy(&defaddr.service, &service_router_prefix, sizeof(struct sockaddr_sv));

    if(create_resolver_rpc(&((struct sv_service_resolver*) res->target)->resolver_id, &defaddr, 0,
            1, &handler->callback, &handler->def_callback.rpc)) {
        LOG_ERR("Could not create server rpc handler - resolver rpc error\n");
        return -1;
    }

    return 0;
}

int server_rpc_handler_initialize(struct server_rpc_handler* handler) {
    assert(handler);

    handler->def_callback.rpc.interface->initialize(handler->def_callback.rpc.target);
    task_mutex_init(&handler->callback_mutex);

    handler->callback_list = g_ptr_array_new_with_free_func(destroy_cb_info);

    callback_info_initialize(&handler->def_callback);

    return 0;
}

void server_rpc_handler_start(struct server_rpc_handler* handler) {
    assert(handler);
    handler->def_callback.rpc.interface->start(handler->def_callback.rpc.target);
}

void server_rpc_handler_stop(struct server_rpc_handler* handler) {
    assert(handler);
    handler->def_callback.rpc.interface->stop(handler->def_callback.rpc.target);
}

int server_rpc_handler_finalize(struct server_rpc_handler* handler) {
    assert(handler);

    task_mutex_destroy(&handler->callback_mutex);
    g_ptr_array_free(handler->callback_list, TRUE);

    callback_info_finalize(&handler->def_callback);
    return 0;
}

static void destroy_cb_info(void* data) {
    if(data == NULL) {
        return;
    }

    struct callback_info* cinfo = (struct callback_info*) data;

    callback_info_finalize(cinfo);
}

static int callback_info_initialize(struct callback_info* cinfo) {
    assert(cinfo);
    if(cinfo->peer.target) {
        if(cinfo->peer.interface->initialize(cinfo->peer.target)) {
            /*TODO error!*/

        }
        cinfo->peer.interface->incref(cinfo->peer.target);
    }

    if(cinfo->rpc.interface->initialize(cinfo->rpc.target)) {

    }
    return 0;
}

static int callback_info_finalize(struct callback_info* cinfo) {
    assert(cinfo);

    if(cinfo->peer.target) {
        cinfo->peer.interface->decref(cinfo->peer.target);

    }

    if(cinfo->rpc.interface->finalize(cinfo->rpc.target)) {

    }
    return 0;
}

static void handle_discover_message(struct server_rpc_handler* handler, service_resolver* peer,
        resolver_rpc* rpc, struct sv_control_header* message, size_t len,
        struct sv_instance_addr* remote) {

    struct sv_discover_message* dmessage = (struct sv_discover_message*) message;
    uint32_t cap = ntohl(dmessage->capabilities);
    uint8_t rel = RELATION_UNKNOWN;
    int created = FALSE;

    /*easy relation check - local is transit, remote is stub */
    if(is_transit(((struct sv_service_resolver*) handler->resolver.target)->capabilities)
            && is_stub(cap)) {
        rel = RELATION_CHILD;
    } else if(is_stub(((struct sv_service_resolver*) handler->resolver.target)->capabilities)
            && is_transit(cap)) {
        rel = RELATION_PARENT;
    }

    struct callback_info* cinfo = NULL;
    task_mutex_lock(&handler->callback_mutex);

    if(peer->target == NULL) {
        /* no peer known - create a peer and only add it in if discover returns success */
        cinfo = (struct callback_info*) malloc(sizeof(*cinfo));

        if(dmessage->resolver_id.flags != SVSF_INVALID) {
            /* it's a propagated discover message - create the peer based on the original source info
             * */

            struct sv_instance_addr peeraddr;
            bzero(&peeraddr, sizeof(peeraddr));
            peeraddr.service.sv_flags = dmessage->resolver_id.flags;
            peeraddr.service.sv_prefix_bits = dmessage->resolver_id.prefix;
            memcpy(&peeraddr.service.sv_srvid, &dmessage->resolver_id.service,
                    sizeof(struct service_id));
            memcpy(&peeraddr.address.sin.sin_addr, &dmessage->resolver_addr.net_ip,
                    sizeof(struct in_addr));

            remote = &peeraddr;
        }

        create_client_service_resolver(
                &((struct sv_service_resolver*) handler->resolver.target)->resolver_id, remote,
                ntohl(dmessage->uptime), cap, ntohl(dmessage->capacity), rel, &cinfo->peer);
        cinfo->peer.interface->initialize(cinfo->peer.target);
        resolver_add_address(cinfo->peer.target, (struct net_addr*) &remote->address.sin.sin_addr);

        resolver_message_callback cb;
        cb.target = cinfo;
        cb.resolver_message_cb = server_resolver_message_cb;

        if(create_resolver_rpc(
                &((struct sv_service_resolver*) handler->resolver.target)->resolver_id, remote,
                RPC_MAX_RETRY, SERVER_REQUEST_TIMEOUT, &cb, &cinfo->rpc)) {
            LOG_ERR("Could not create resolver rpc!\n");

        }

        callback_info_initialize(cinfo);

        int scount = NUM_SERVICES(dmessage, len);

        struct service_desc* sdesc;
        int i = 0;
        for(; i < scount; i++) {
            /* need to copy the memory */
            sdesc = (struct service_desc*) malloc(sizeof(*sdesc));

            memcpy(sdesc, &dmessage->service_prefixes[i], sizeof(*sdesc));

            sdesc->type = ntohs(dmessage->service_prefixes[i].type);

            resolver_add_service_desc(cinfo->peer.target, sdesc);
        }

        peer = &cinfo->peer;

        created = TRUE;
    } else {
        /*check if the relationship, etc has changed? locking? TODO*/
        struct sv_base_service_resolver * pres = (struct sv_base_service_resolver*) peer->target;

        peer->interface->set_uptime(peer->target, ntohl(dmessage->uptime));
        pres->resolver.capabilities = cap;
        pres->resolver.relation = rel;

        /* TODO - update the service descs?*/
        /* TODO - add new addresses?*/
    }

    peer->interface->incref(peer->target);
    int retval = handler->resolver.interface->peer_discovered(handler->resolver.target, peer,
            ntohs(dmessage->flags));
    peer->interface->decref(peer->target);

    if(created) {
        if(retval == 0) {
            g_ptr_array_add(handler->callback_list, cinfo);
        } else {
            /* finalize */
            callback_info_finalize(cinfo);
            free(cinfo);
        }
    }

    task_mutex_unlock(&handler->callback_mutex);

}

static void send_error_reply(resolver_rpc* rpc, uint32_t xid, uint16_t err_type, uint16_t msg_type,
        const char* message) {

    int msize = message == NULL ? 0 : strlen(message);
    struct sv_error_reply* emsg = (struct sv_error_reply*) malloc(sizeof(*emsg) + msize);
    init_control_header(&emsg->header, SV_ERROR, xid, sizeof(*emsg) + msize);

    emsg->error_type = htons(err_type);
    emsg->message_type = htons(msg_type);
    emsg->header.xid = htonl(xid);

    if(msize > 0) {
        memcpy(&emsg->body, message, msize);
    }

    /* error message? - note that this is only valid if the receipt is single-threaded */
    rpc->interface->send_resolver_message(rpc->target, xid, &emsg->header, sizeof(*emsg), NULL);
}

static void handle_disappear_message(struct server_rpc_handler* handler, service_resolver* peer,
        resolver_rpc* rpc, struct sv_control_header* message, size_t len,
        struct sv_instance_addr* remote) {

    struct sv_disappear_message* dmessage = (struct sv_disappear_message*) message;

    if(peer->target == NULL) {
        /* send error */
        send_error_reply(rpc, ntohl(message->xid), SV_ERR_UNAUTHORIZED, ntohs(message->type),
                "Peer resolver unknown");
        return;
    }

    /* peer disappered may trigger a removal... */
    task_mutex_lock(&handler->callback_mutex);

    /* determine the true missing peer */
    if(dmessage->resolver_id.flags != SVSF_INVALID) {
        /*find the real peer */

        peer = handler->resolver.interface->get_peer(handler->resolver.target,
                &dmessage->resolver_id.service);

        if(peer == NULL) {
            send_error_reply(rpc, ntohl(message->xid), SV_ERR_UNAUTHORIZED, ntohs(message->type),
                    "Peer resolver unknown");
            goto out;
        }
    }

    peer->interface->incref(peer->target);

    /* check to see if the "disappearing" address is all or just one */
    struct net_addr addr;
    bzero(&addr, 0);
    if(memcmp(&addr, &dmessage->resolver_addr, sizeof(addr)) == 0) {
        resolver_clear_addresses(peer->target);
    } else {
        resolver_remove_address(peer->target, &addr);
    }

    if(resolver_get_address_count(peer->target) == 0) {

        handler->resolver.interface->peer_disappeared(handler->resolver.target, peer,
                ntohs(dmessage->flags));
    }

    peer->interface->decref(peer->target);

    out: task_mutex_unlock(&handler->callback_mutex);
}

static void handle_echo_request(struct server_rpc_handler* handler, service_resolver* peer,
        resolver_rpc* rpc, struct sv_control_header* message, size_t len,
        struct sv_instance_addr* remote) {

    if(peer->target == NULL) {
        /* send error - unknown peer */
        send_error_reply(rpc, ntohl(message->xid), SV_ERR_UNAUTHORIZED, ntohs(message->type),
                "Peer resolver unknown");
        return;
    }

    /* set last update and rtt estimate */
    struct sv_echo_message* emessage = (struct sv_echo_message*) message;

    uint32_t count = ntohl(emessage->count);

    peer->interface->incref(peer->target);

    int retval = handler->resolver.interface->poke_resolver(handler->resolver.target, peer, count);

    peer->interface->decref(peer->target);

    uint32_t xid = ntohl(emessage->header.xid);

    if(retval < 0) {
        /*error */
        send_error_reply(rpc, xid, -retval, ntohs(message->type), NULL);
        /* check ret val?*/
    } else {
        emessage = (struct sv_echo_message*) malloc(sizeof(*emessage));
        init_control_header(&emessage->header, SV_ECHO_REPLY, xid, sizeof(*emessage));
        emessage->count = htonl(count);

        retval = rpc->interface->send_resolver_message(rpc->target, xid, &emessage->header,
                sizeof(*emessage), NULL);
    }
}

static void handle_register_request(struct server_rpc_handler* handler, service_resolver* peer,
        resolver_rpc* rpc, struct sv_control_header* message, size_t len,
        struct sv_instance_addr* remote) {

    if(peer->target == NULL) {
        /* send error - unknown peer */
        send_error_reply(rpc, ntohl(message->xid), SV_ERR_UNAUTHORIZED, ntohs(message->type),
                "Peer resolver unknown");
        return;
    }

    /* set last update and rtt estimate */
    struct sv_register_message* rmessage = (struct sv_register_message*) message;

    int scount = NUM_SERVICES(rmessage, len);
    int i = 0;
    for(; i < scount; i++) {
        /* need to copy the memory */
        rmessage->service_ids[i].type = ntohs(rmessage->service_ids[i].type);
    }

    peer->interface->incref(peer->target);
    int retval = handler->resolver.interface->register_services(handler->resolver.target, peer,
            rmessage->service_ids, scount, &rmessage->address, ntohl(rmessage->ttl));

    peer->interface->decref(peer->target);

    uint32_t xid = ntohl(rmessage->header.xid);

    if(retval < 0) {
        /*error */
        send_error_reply(rpc, xid, -retval, ntohs(message->type), NULL);
        /* check ret val?*/
    } else {
        message = (struct sv_control_header*) malloc(sizeof(*message));
        init_control_header(message, SV_ACK, xid, sizeof(*message));

        retval = rpc->interface->send_resolver_message(rpc->target, xid, message, sizeof(*message),
                NULL);
    }

}

static void handle_unregister_request(struct server_rpc_handler* handler, service_resolver* peer,
        resolver_rpc* rpc, struct sv_control_header* message, size_t len,
        struct sv_instance_addr* remote) {

    if(peer->target == NULL) {
        /* send error - unknown peer */
        send_error_reply(rpc, ntohl(message->xid), SV_ERR_UNAUTHORIZED, ntohs(message->type),
                "Peer resolver unknown");
        return;
    }

    /* set last update and rtt estimate */
    struct sv_unregister_message* rmessage = (struct sv_unregister_message*) message;
    int scount = NUM_SERVICES(rmessage, len);
    int i = 0;
    for(; i < scount; i++) {
        /* need to copy the memory */
        rmessage->service_ids[i].type = ntohs(rmessage->service_ids[i].type);
    }

    peer->interface->incref(peer->target);
    int retval = handler->resolver.interface->unregister_services(handler->resolver.target, peer,
            rmessage->service_ids, scount, &rmessage->address);

    peer->interface->decref(peer->target);

    uint32_t xid = ntohl(rmessage->header.xid);

    if(retval < 0) {
        /*error */
        send_error_reply(rpc, xid, -retval, ntohs(message->type), NULL);
        /* check ret val?*/
    } else {
        message = (struct sv_control_header*) malloc(sizeof(*message));
        init_control_header(message, SV_ACK, xid, sizeof(*message));

        retval = rpc->interface->send_resolver_message(rpc->target, xid, message, sizeof(*message),
                NULL);
    }

}

static void handle_update_request(struct server_rpc_handler* handler, service_resolver* peer,
        resolver_rpc* rpc, struct sv_control_header* message, size_t len,
        struct sv_instance_addr* remote) {

    if(peer->target == NULL) {
        /* send error - unknown peer */
        send_error_reply(rpc, ntohl(message->xid), SV_ERR_UNAUTHORIZED, ntohs(message->type),
                "Peer resolver unknown");
        return;
    }

    /* set last update and rtt estimate */
    struct sv_update_request* umessage = (struct sv_update_request*) message;
    uint16_t stype = ntohs(umessage->type);
    int scount = NUM_SERVICES(umessage, len);
    int i = 0;
    for(; i < scount; i++) {
        umessage->service_ids[i].type = ntohs(umessage->service_ids[i].type);
    }

    int statsize = get_stat_size(stype);
    uint32_t xid = ntohl(umessage->header.xid);

    int size = sizeof(*umessage) + scount * statsize;

    struct sv_update_message* smessage = (struct sv_update_message*) malloc(size);

    stat_response resp;
    resp.type = stype;
    resp.count = scount;
    resp.data = smessage->body;

    peer->interface->incref(peer->target);
    int retval = handler->resolver.interface->get_service_updates(handler->resolver.target, peer,
            stype, umessage->service_ids, scount, &resp);

    peer->interface->decref(peer->target);

    if(retval <= 0) {
        /*error */
        free(smessage);
        send_error_reply(rpc, xid, -retval, ntohs(message->type), NULL);
        /* check ret val?*/
    } else {
        /* is this correct here is it always aysnc? TODO */
        size = sizeof(*smessage) + retval * statsize;
        init_control_header(&smessage->header, SV_UPDATE_MESSAGE, xid, size);

        for(i = 0; i < retval; i++) {
            prep_stats_for_network(stype, smessage->body + (i * statsize), resp.data + (i
                    * statsize));
        }

        smessage->type = htons(stype);

        retval = rpc->interface->send_resolver_message(rpc->target, xid, &smessage->header, size,
                NULL);
    }

}

static void handle_update_message(struct server_rpc_handler* handler, service_resolver* peer,
        resolver_rpc* rpc, struct sv_control_header* message, size_t len,
        struct sv_instance_addr* remote) {

    if(peer->target == NULL) {
        /* send error - unknown peer */
        send_error_reply(rpc, ntohl(message->xid), SV_ERR_UNAUTHORIZED, ntohs(message->type),
                "Peer resolver unknown");
        return;
    }

    /* set last update and rtt estimate */
    struct sv_update_message* umessage = (struct sv_update_message*) message;
    uint16_t stype = ntohs(umessage->type);

    int statsize = get_stat_size(stype);
    int scount = (len - sizeof(*umessage)) / statsize;
    uint32_t xid = ntohl(umessage->header.xid);

    stat_response resp;
    resp.count = scount;
    resp.type = stype;
    resp.data = umessage->body;
    int i = 0;
    for(; i < scount; i++) {
        prep_stats_for_host(stype, resp.data + (i * statsize), umessage->body + (i * statsize));
    }

    peer->interface->incref(peer->target);
    int retval = handler->resolver.interface->update_services(handler->resolver.target, peer,
            stype, &resp);

    peer->interface->decref(peer->target);

    if(retval <= 0) {
        /*error */
        send_error_reply(rpc, xid, -retval, ntohs(message->type), NULL);
        /* check ret val?*/
    }
}

static void handle_query_request(struct server_rpc_handler* handler, service_resolver* peer,
        resolver_rpc* rpc, struct sv_control_header* message, size_t len,
        struct sv_instance_addr* remote) {

    if(peer->target == NULL) {
        /* send error - unknown peer */
        send_error_reply(rpc, ntohl(message->xid), SV_ERR_UNAUTHORIZED, ntohs(message->type),
                "Peer resolver unknown");
        return;
    }

    struct sv_query_request* qmessage = (struct sv_query_request*) message;

    int scount = NUM_SERVICES(qmessage, len);
    int i = 0;
    for(; i < scount; i++) {
        qmessage->service_ids[i].type = ntohs(qmessage->service_ids[i].type);
    }

    uint32_t xid = ntohl(qmessage->header.xid);

    peer->interface->incref(peer->target);
    int retval = handler->resolver.interface->query_services(handler->resolver.target, peer,
            qmessage->service_ids, scount);

    peer->interface->decref(peer->target);

    if(retval <= 0) {
        /*error */
        send_error_reply(rpc, xid, -retval, ntohs(message->type), NULL);
        /* check ret val?*/
    } else {
        /* is this correct here is it always aysnc? TODO */
        int size = sizeof(struct sv_query_response) + scount * sizeof(struct service_desc);
        struct sv_query_response* qresp = (struct sv_query_response*) malloc(size);
        bzero(qresp, sizeof(*qresp));
        init_control_header(&qresp->header, SV_QUERY_REPLY, xid, size);
        memcpy(&qresp->service_ids, &qmessage->service_ids, scount * sizeof(struct service_desc));

        for(i = 0; i < scount; i++) {
            qresp->service_ids[i].type = htons(qmessage->service_ids[i].type);
        }

        retval
                = rpc->interface->send_resolver_message(rpc->target, xid, &qresp->header, size,
                        NULL);
    }
}

static void handle_resolution_request(struct server_rpc_handler* handler, service_resolver* peer,
        resolver_rpc* rpc, struct sv_control_header* message, size_t len,
        struct sv_instance_addr* remote) {

    if(peer->target == NULL) {
        /* send error - unknown peer */
        send_error_reply(rpc, ntohl(message->xid), SV_ERR_UNAUTHORIZED, ntohs(message->type),
                "Peer resolver unknown");
        return;
    }

    struct sv_resolution_request* rmessage = (struct sv_resolution_request*) message;

    rmessage->service_id.type = ntohs(rmessage->service_id.type);

    uint32_t xid = ntohl(rmessage->header.xid);

    struct net_addr addr;
    peer->interface->incref(peer->target);
    int retval = handler->resolver.interface->resolve_service(handler->resolver.target, peer,
            &rmessage->service_id, &addr);

    peer->interface->decref(peer->target);

    if(retval <= 0) {
        /*error */
        send_error_reply(rpc, xid, -retval, ntohs(message->type), NULL);
        /* check ret val?*/
    } else {
        /* is this correct here is it always aysnc? TODO */

        struct sv_resolution_response* rresp = (struct sv_resolution_response*) malloc(
                sizeof(*rresp));
        bzero(rresp, sizeof(*rresp));
        init_control_header(&rresp->header, SV_RESOLUTION_REPLY, xid, sizeof(*rresp));

        memcpy(&rresp->service_id, &rmessage->service_id, sizeof(struct service_desc));
        memcpy(&rresp->address, &addr, sizeof(addr));
        rresp->service_id.type = htons(rmessage->service_id.type);

        retval = rpc->interface->send_resolver_message(rpc->target, xid, &rresp->header,
                sizeof(*rresp), NULL);
    }
}

static void server_resolver_message_cb(void* target, uint16_t type,
        struct sv_control_header* message, size_t len, struct sv_instance_addr* remote) {
    assert(target);

    struct callback_info* cinfo = (struct callback_info*) target;

    if(cinfo->peer.target != NULL) {
        ((struct sv_service_resolver*) cinfo->peer.target)->last_access = get_current_time_ms();
    }

    switch(type) {
        case SV_DISCOVER_MESSAGE:
            handle_discover_message(cinfo->handler, &cinfo->peer, &cinfo->rpc, message, len, remote);
            return;
        case SV_DISAPPEAR_MESSAGE:
            handle_disappear_message(cinfo->handler, &cinfo->peer, &cinfo->rpc, message, len,
                    remote);
            return;
        case SV_ECHO_REQUEST:
            handle_echo_request(cinfo->handler, &cinfo->peer, &cinfo->rpc, message, len, remote);
            return;
            //service registration - authorization and authentication
        case SV_REGISTER_REQUEST:
            handle_register_request(cinfo->handler, &cinfo->peer, &cinfo->rpc, message, len, remote);
            return;
        case SV_UNREGISTER_REQUEST:
            handle_unregister_request(cinfo->handler, &cinfo->peer, &cinfo->rpc, message, len,
                    remote);
            return;
            //service update (load and meta/stat info)
        case SV_UPDATE_REQUEST:
            handle_update_request(cinfo->handler, &cinfo->peer, &cinfo->rpc, message, len, remote);
            return;
        case SV_UPDATE_MESSAGE:
            handle_update_message(cinfo->handler, &cinfo->peer, &cinfo->rpc, message, len, remote);
            return;
            //service query
        case SV_QUERY_REQUEST:
            handle_query_request(cinfo->handler, &cinfo->peer, &cinfo->rpc, message, len, remote);
            return;
        case SV_RESOLUTION_REQUEST:
            handle_resolution_request(cinfo->handler, &cinfo->peer, &cinfo->rpc, message, len,
                    remote);
            return;
        default:
            LOG_ERR("Invalid request message type: %u", type);
    }
}
