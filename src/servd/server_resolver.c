/*
 * server_resolver.c
 *
 *  Created on: Feb 23, 2011
 *      Author: daveds
 */

#include "server_resolver.h"
#include "time_util.h"
#include "service_util.h"
#include "task.h"
#include "debug.h"

#include <assert.h>

extern service_resolver* create_client_service_resolver(struct sockaddr_sv* local,
        struct sv_instance_addr* remote, uint32_t uptime, uint32_t capabilities, uint32_t capacity,
        uint8_t relation);

extern resolver_rpc* create_resolver_rpc(struct sockaddr_sv* local,
        struct sv_instance_addr* remote, uint16_t rpc_max_retry, uint16_t request_timeout,
        resolver_message_callback* cb);

static void server_resolver_message_cb(resolver_message_callback* cb, uint16_t type,
        struct sv_control_header* message, size_t len, struct sv_instance_addr* remote);
static void server_resolver_peer_status_cb(struct sv_peer_status_callback* cb,
        service_resolver* peer, enum resolver_state state);

static int callback_info_initialize(struct callback_info* cinfo);
static int callback_info_finalize(struct callback_info* cinfo);
static void destroy_cb_info(void* data);

struct server_rpc_handler* create_server_rpc_handler(service_resolver* res) {
    if(res == NULL) {
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
    handler->resolver = res;

    handler->def_callback.handler = handler;

    handler->callback.target = &handler->def_callback;
    handler->callback.resolver_message_cb = server_resolver_message_cb;

    handler->status_callback.target = handler;
    handler->status_callback.peer_status_cb = server_resolver_peer_status_cb;

    resolver_register_peer_status_callback(res, &handler->status_callback);

    struct sv_instance_addr defaddr;
    bzero(&defaddr, sizeof(defaddr));

    memcpy(&defaddr.service, &service_router_prefix, sizeof(struct sockaddr_sv));

    if(!(handler->def_callback.rpc = create_resolver_rpc(&res->resolver.resolver_id, &defaddr, 0,
            1, &handler->callback))) {
        LOG_ERR("Could not create server rpc handler - resolver rpc error\n");
        return -1;
    }

    return 0;
}

int server_rpc_handler_initialize(struct server_rpc_handler* handler) {
    assert(handler);

    handler->def_callback.rpc->interface->initialize(handler->def_callback.rpc);
    task_mutex_init(&handler->callback_mutex);

    handler->callback_list = g_ptr_array_new_with_free_func(destroy_cb_info);
    callback_info_initialize(&handler->def_callback);

    return 0;
}

void server_rpc_handler_start(struct server_rpc_handler* handler) {
    assert(handler);
    handler->def_callback.rpc->interface->start(handler->def_callback.rpc);
}

void server_rpc_handler_stop(struct server_rpc_handler* handler) {
    assert(handler);
    handler->def_callback.rpc->interface->stop(handler->def_callback.rpc);
}

int server_rpc_handler_finalize(struct server_rpc_handler* handler) {
    assert(handler);

    task_mutex_destroy(&handler->callback_mutex);

    g_ptr_array_remove_range(handler->callback_list, 0, handler->callback_list->len);
    g_ptr_array_free(handler->callback_list, TRUE);

    callback_info_finalize(&handler->def_callback);

    resolver_unregister_peer_status_callback(handler->resolver, &handler->status_callback);
    return 0;
}

static void destroy_cb_info(void* data) {
    if(data == NULL) {
        return;
    }

    struct callback_info* cinfo = (struct callback_info*) data;

    callback_info_finalize(cinfo);
    free(cinfo);
}

static int callback_info_initialize(struct callback_info* cinfo) {
    assert(cinfo);
    if(cinfo->peer) {
        if(cinfo->peer->interface->initialize(cinfo->peer)) {
            /*TODO error!*/

        }
        cinfo->peer->interface->incref(cinfo->peer);
    }

    if(cinfo->rpc->interface->initialize(cinfo->rpc)) {

    }
    return 0;
}

static int callback_info_finalize(struct callback_info* cinfo) {
    assert(cinfo);

    if(cinfo->peer) {
        if(cinfo->peer->resolver.state == ACTIVE) {
            cinfo->peer->interface->stop(cinfo->peer);
        }
        cinfo->peer->interface->decref(cinfo->peer);
    }

    if(cinfo->rpc) {
        if(is_started(cinfo->rpc->resolver.state)) {
            cinfo->rpc->interface->stop(cinfo->rpc);
        }
        if(cinfo->rpc->interface->finalize(cinfo->rpc)) {

        }
        free(cinfo->rpc);
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
    if(is_transit(handler->resolver->resolver.capabilities) && is_stub(cap)) {
        rel = RELATION_CHILD;
    } else if(is_stub(handler->resolver->resolver.capabilities) && is_transit(cap)) {
        rel = RELATION_PARENT;
    } else if(is_stub(handler->resolver->resolver.capabilities) && is_stub(cap)) {
        //drop peer relations if the local resolver is a stub
        LOG_DBG("Stub resolver %s dropping peer discovery %s\n", service_id_to_str(&handler->resolver->resolver.resolver_id.sv_srvid),
                service_id_to_str(&remote->service.sv_srvid));
        return;
    }

    struct callback_info* cinfo = NULL;
    struct sv_instance_addr peeraddr;

    task_mutex_lock(&handler->callback_mutex);

    if(peer == NULL) {
        /* no peer known - create a peer and only add it in if discover returns success */
        cinfo = (struct callback_info*) malloc(sizeof(*cinfo));

        if(dmessage->resolver_id.flags != SVSF_INVALID) {
            /* it's a propagated discover message - create the peer based on the original source info
             * */

            bzero(&peeraddr, sizeof(peeraddr));
            peeraddr.service.sv_family = AF_SERVAL;
            peeraddr.service.sv_flags = dmessage->resolver_id.flags;
            peeraddr.service.sv_prefix_bits = dmessage->resolver_id.prefix;
            memcpy(&peeraddr.service.sv_srvid, &dmessage->resolver_id.service,
                    sizeof(struct service_id));

            peeraddr.address.sin.sin_family = AF_INET;
            memcpy(&peeraddr.address.sin.sin_addr, &dmessage->resolver_addr.net_ip,
                    sizeof(struct in_addr));

            remote = &peeraddr;
        }

        if(!(cinfo->peer = create_client_service_resolver(
                &((struct sv_service_resolver*) handler->resolver)->resolver_id, remote,
                ntohl(dmessage->uptime), cap, ntohl(dmessage->capacity), rel))) {
            LOG_ERR("Could not create peer!\n");
            free(cinfo);
            goto out;
        }

        resolver_add_address(cinfo->peer, (struct net_addr*) &remote->address.sin.sin_addr);

        resolver_message_callback cb;
        cb.target = cinfo;
        cb.resolver_message_cb = server_resolver_message_cb;

        if(!(cinfo->rpc = create_resolver_rpc(
                &((struct sv_service_resolver*) handler->resolver)->resolver_id, remote,
                RPC_MAX_RETRY, SERVER_REQUEST_TIMEOUT, &cb))) {
            LOG_ERR("Could not create resolver rpc!\n");
            free(cinfo);
            goto out;
        }

        /*inits the peer and rpc*/
        callback_info_initialize(cinfo);

        //cinfo->peer->resolver.state = DISCOVERED;
        cinfo->peer->interface->start(cinfo->peer);

        int scount = NUM_SERVICES(dmessage, len);

        struct service_desc* sdesc;
        int i = 0;
        for(; i < scount; i++) {
            /* need to copy the memory */
            sdesc = (struct service_desc*) malloc(sizeof(*sdesc));

            memcpy(sdesc, &dmessage->service_prefixes[i], sizeof(*sdesc));

            sdesc->type = ntohs(dmessage->service_prefixes[i].type);

            resolver_add_service_desc(cinfo->peer, sdesc);
        }

        peer = cinfo->peer;

        created = TRUE;
    } else {
        /*check if the relationship, etc has changed? locking? TODO*/
        //struct sv_base_service_resolver * pres = (struct sv_base_service_resolver*) peer;

        peer->interface->set_uptime(peer, ntohl(dmessage->uptime));
        peer->resolver.capabilities = cap;
        peer->resolver.relation = rel;

        /* TODO - update the service descs?*/
        /* TODO - add new addresses?*/
    }

    peer->interface->incref(peer);
    int retval = handler->resolver->interface->peer_discovered(handler->resolver, peer,
            ntohs(dmessage->flags));
    peer->interface->decref(peer);

    if(created) {
        if(retval == 0) {
            g_ptr_array_add(handler->callback_list, cinfo);
        } else {
            /* finalize */
            callback_info_finalize(cinfo);
            free(cinfo);
        }
    }

    out: task_mutex_unlock(&handler->callback_mutex);

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
    rpc->interface->send_resolver_message(rpc, xid, &emsg->header, sizeof(*emsg), NULL);
}

static void handle_disappear_message(struct server_rpc_handler* handler, service_resolver* peer,
        resolver_rpc* rpc, struct sv_control_header* message, size_t len,
        struct sv_instance_addr* remote) {

    struct sv_disappear_message* dmessage = (struct sv_disappear_message*) message;

    if(peer == NULL) {
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

        peer = handler->resolver->interface->get_peer(handler->resolver,
                &dmessage->resolver_id.service);

        if(peer == NULL) {
            send_error_reply(rpc, ntohl(message->xid), SV_ERR_UNAUTHORIZED, ntohs(message->type),
                    "Peer resolver unknown");
            goto out;
        }
    }

    peer->interface->incref(peer);

    /* check to see if the "disappearing" address is all or just one */
    struct net_addr addr;
    bzero(&addr, 0);
    if(memcmp(&addr, &dmessage->resolver_addr, sizeof(addr)) == 0) {
        resolver_clear_addresses(peer);
    } else {
        resolver_remove_address(peer, &addr);
    }

    if(resolver_get_address_count(peer) == 0) {

        handler->resolver->interface->peer_disappeared(handler->resolver, peer,
                ntohs(dmessage->flags));
    }

    peer->interface->decref(peer);

    out: task_mutex_unlock(&handler->callback_mutex);
}

static void handle_echo_request(struct server_rpc_handler* handler, service_resolver* peer,
        resolver_rpc* rpc, struct sv_control_header* message, size_t len,
        struct sv_instance_addr* remote) {

    if(peer == NULL) {
        /* send error - unknown peer */
        send_error_reply(rpc, ntohl(message->xid), SV_ERR_UNAUTHORIZED, ntohs(message->type),
                "Peer resolver unknown");
        return;
    }

    /* set last update and rtt estimate */
    struct sv_echo_message* emessage = (struct sv_echo_message*) message;

    uint32_t count = ntohl(emessage->count);

    peer->interface->incref(peer);

    int retval = handler->resolver->interface->poke_resolver(handler->resolver, peer, count);

    peer->interface->decref(peer);

    uint32_t xid = ntohl(emessage->header.xid);

    if(retval < 0) {
        /*error */
        send_error_reply(rpc, xid, -retval, ntohs(message->type), NULL);
        /* check ret val?*/
    } else {
        emessage = (struct sv_echo_message*) malloc(sizeof(*emessage));
        init_control_header(&emessage->header, SV_ECHO_REPLY, xid, sizeof(*emessage));
        emessage->count = htonl(count);

        retval = rpc->interface->send_resolver_message(rpc, xid, &emessage->header,
                sizeof(*emessage), NULL);
    }
}

static void handle_register_request(struct server_rpc_handler* handler, service_resolver* peer,
        resolver_rpc* rpc, struct sv_control_header* message, size_t len,
        struct sv_instance_addr* remote) {

    if(peer == NULL) {
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

    peer->interface->incref(peer);
    int retval = handler->resolver->interface->register_services(handler->resolver, peer,
            rmessage->service_ids, scount, &rmessage->address, ntohl(rmessage->ttl));

    peer->interface->decref(peer);

    uint32_t xid = ntohl(rmessage->header.xid);

    if(retval < 0) {
        /*error */
        send_error_reply(rpc, xid, -retval, ntohs(message->type), NULL);
        /* check ret val?*/
    } else {
        message = (struct sv_control_header*) malloc(sizeof(*message));
        init_control_header(message, SV_ACK, xid, sizeof(*message));

        retval = rpc->interface->send_resolver_message(rpc, xid, message, sizeof(*message), NULL);
    }

}

static void handle_unregister_request(struct server_rpc_handler* handler, service_resolver* peer,
        resolver_rpc* rpc, struct sv_control_header* message, size_t len,
        struct sv_instance_addr* remote) {

    if(peer == NULL) {
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

    peer->interface->incref(peer);
    int retval = handler->resolver->interface->unregister_services(handler->resolver, peer,
            rmessage->service_ids, scount, &rmessage->address);

    peer->interface->decref(peer);

    uint32_t xid = ntohl(rmessage->header.xid);

    if(retval < 0) {
        /*error */
        send_error_reply(rpc, xid, -retval, ntohs(message->type), NULL);
        /* check ret val?*/
    } else {
        message = (struct sv_control_header*) malloc(sizeof(*message));
        init_control_header(message, SV_ACK, xid, sizeof(*message));

        retval = rpc->interface->send_resolver_message(rpc, xid, message, sizeof(*message), NULL);
    }

}

static void handle_update_request(struct server_rpc_handler* handler, service_resolver* peer,
        resolver_rpc* rpc, struct sv_control_header* message, size_t len,
        struct sv_instance_addr* remote) {

    if(peer == NULL) {
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

    peer->interface->incref(peer);
    int retval = handler->resolver->interface->get_service_updates(handler->resolver, peer, stype,
            umessage->service_ids, scount, &resp);

    peer->interface->decref(peer);

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

        retval = rpc->interface->send_resolver_message(rpc, xid, &smessage->header, size, NULL);
    }

}

static void handle_update_message(struct server_rpc_handler* handler, service_resolver* peer,
        resolver_rpc* rpc, struct sv_control_header* message, size_t len,
        struct sv_instance_addr* remote) {

    if(peer == NULL) {
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

    peer->interface->incref(peer);
    int retval = handler->resolver->interface->update_services(handler->resolver, peer, stype,
            &resp);

    peer->interface->decref(peer);

    if(retval <= 0) {
        /*error */
        send_error_reply(rpc, xid, -retval, ntohs(message->type), NULL);
        /* check ret val?*/
    }
}

static void handle_query_request(struct server_rpc_handler* handler, service_resolver* peer,
        resolver_rpc* rpc, struct sv_control_header* message, size_t len,
        struct sv_instance_addr* remote) {

    if(peer == NULL) {
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

    peer->interface->incref(peer);
    int retval = handler->resolver->interface->query_services(handler->resolver, peer,
            qmessage->service_ids, scount);

    peer->interface->decref(peer);

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

        retval = rpc->interface->send_resolver_message(rpc, xid, &qresp->header, size, NULL);
    }
}

static void handle_resolution_request(struct server_rpc_handler* handler, service_resolver* peer,
        resolver_rpc* rpc, struct sv_control_header* message, size_t len,
        struct sv_instance_addr* remote) {

    if(peer == NULL) {
        /* send error - unknown peer */
        send_error_reply(rpc, ntohl(message->xid), SV_ERR_UNAUTHORIZED, ntohs(message->type),
                "Peer resolver unknown");
        return;
    }

    struct sv_resolution_request* rmessage = (struct sv_resolution_request*) message;

    rmessage->service_id.type = ntohs(rmessage->service_id.type);

    uint32_t xid = ntohl(rmessage->header.xid);

    struct net_addr addr;
    peer->interface->incref(peer);
    int retval = handler->resolver->interface->resolve_service(handler->resolver, peer,
            &rmessage->service_id, &addr);

    peer->interface->decref(peer);

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

        retval = rpc->interface->send_resolver_message(rpc, xid, &rresp->header, sizeof(*rresp),
                NULL);
    }
}

static int find_cinfo_by_peer(struct server_rpc_handler* handler, service_resolver* peer) {
    assert(handler);

    if(peer == NULL) {
        return -1;
    }

    int i = 0;
    struct callback_info* cinfo;
    for(i = 0; i < handler->callback_list->len; i++) {
        cinfo = (struct callback_info*) g_ptr_array_index(handler->callback_list, i);
        if(cinfo->peer == peer) {
            return i;
        }
    }
    return -1;
}

static void server_resolver_peer_status_cb(struct sv_peer_status_callback* cb,
        service_resolver* peer, enum resolver_state state) {

    assert(cb);

    struct server_rpc_handler* handler = (struct server_rpc_handler*) cb->target;

    task_mutex_lock(&handler->callback_mutex);

    if(state >= UNRESPONSIVE) {
        //purge the callback info
        int index = find_cinfo_by_peer(handler, peer);

        if(index < 0) {
            LOG_ERR("Could not find peer %s that should have been in the cinfo list!\n", service_id_to_str(&peer->resolver.resolver_id.sv_srvid));
            goto out;
        }

        g_ptr_array_remove_index(handler->callback_list, index);
    }

    out: task_mutex_unlock(&handler->callback_mutex);
}

static void server_resolver_message_cb(resolver_message_callback* cb, uint16_t type,
        struct sv_control_header* message, size_t len, struct sv_instance_addr* remote) {
    assert(cb);

    struct callback_info* cinfo = (struct callback_info*) cb->target;

    if(cinfo->peer != NULL) {
        cinfo->peer->resolver.last_access = get_current_time_ms();
    }

    switch(type) {
        case SV_DISCOVER_MESSAGE:
            handle_discover_message(cinfo->handler, cinfo->peer, cinfo->rpc, message, len, remote);
            return;
        case SV_DISAPPEAR_MESSAGE:
            handle_disappear_message(cinfo->handler, cinfo->peer, cinfo->rpc, message, len, remote);
            return;
        case SV_ECHO_REQUEST:
            handle_echo_request(cinfo->handler, cinfo->peer, cinfo->rpc, message, len, remote);
            return;
            //service registration - authorization and authentication
        case SV_REGISTER_REQUEST:
            handle_register_request(cinfo->handler, cinfo->peer, cinfo->rpc, message, len, remote);
            return;
        case SV_UNREGISTER_REQUEST:
            handle_unregister_request(cinfo->handler, cinfo->peer, cinfo->rpc, message, len, remote);
            return;
            //service update (load and meta/stat info)
        case SV_UPDATE_REQUEST:
            handle_update_request(cinfo->handler, cinfo->peer, cinfo->rpc, message, len, remote);
            return;
        case SV_UPDATE_MESSAGE:
            handle_update_message(cinfo->handler, cinfo->peer, cinfo->rpc, message, len, remote);
            return;
            //service query
        case SV_QUERY_REQUEST:
            handle_query_request(cinfo->handler, cinfo->peer, cinfo->rpc, message, len, remote);
            return;
        case SV_RESOLUTION_REQUEST:
            handle_resolution_request(cinfo->handler, cinfo->peer, cinfo->rpc, message, len, remote);
            return;
        default:
            LOG_ERR("Invalid request message type: %u", type);
    }
}
