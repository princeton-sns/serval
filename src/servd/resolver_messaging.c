/*
 * resolver_messaging.c
 *
 *  Created on: Feb 11, 2011
 *      Author: daveds
 */

#include <sys/time.h>
#include <assert.h>
#include <limits.h>
#include <glib.h>

#include "resolver_messaging.h"
#include "message_channel.h"
#include "debug.h"
#include "time_util.h"

extern int create_udp_message_channel(struct sockaddr_sv* local,
        struct sv_instance_addr* remote, int buffer_len,
        message_channel_callback* callback, message_channel* channel);

//TODO - max outstanding response/requests?
//    task_mutex res_mutex;
//        GHashTable* rpc_request_map;
//    uint32_t outstanding_responses;
//uint32_t rpc_expire_timeout;

struct sv_resolver_rpc {
    task_mutex req_mutex;

    //keyed by transactionID
    GHashTable* rpc_request_map;

    //typedef hash_map<uint16_t, TestStats> StatMap;
    //transaction id boundary?

    uint64_t last_remote_access;
    uint32_t outstanding_requests;

    uint16_t max_retry;
    uint16_t request_timeout;

    /* the message channel must be serval compatible
     * should be effectively shared between req/resp
     * */
    message_channel channel;
    /* only needed for incoming requests */
    resolver_message_callback callback;
};

//static uint32_t get_outstanding_responses(struct sv_resolver_messaging* resm);
//static uint32_t base_get_rpc_expire_timeout(struct sv_resolver_messaging* resm);
//static void base_set_rpc_expire_timeout(struct sv_resolver_messaging* resm, uint32_t timeout);

static uint32_t get_outstanding_requests(void* resm);

static uint16_t get_max_retry(void* resm);
static void set_max_retry(void* resm, uint16_t retry);

static uint16_t get_request_timeout(void* resm);
static void set_request_timeout(void* resm, uint16_t timeout);

static int finalize(void* messenger);
static int initialize(void* messenger);
static void stop(void* messenger);

static void start(void* messenger);

static int send_resolver_request(void* messenger, uint32_t xid,
        struct sv_control_header* message, size_t len,
        resolver_message_callback* cb);

static int send_resolver_response(void* messenger, uint32_t xid,
        struct sv_control_header* message, size_t len,
        resolver_message_callback* cb);

static struct sv_resolver_rpc_interface client_rpc_interface = {

.initialize = initialize, .start = start, .stop = stop, .finalize = finalize,
        .get_outstanding_requests = get_outstanding_requests, .get_max_retry =
                get_max_retry, .set_max_retry = set_max_retry,
        .get_request_timeout = get_request_timeout, .set_request_timeout =
                set_request_timeout, .send_resolver_message =
                send_resolver_request, };

static struct sv_resolver_rpc_interface server_rpc_interface = {

.initialize = initialize, .start = start, .stop = stop, .finalize = finalize,
        .get_outstanding_requests = get_outstanding_requests, .get_max_retry =
                get_max_retry, .set_max_retry = set_max_retry,
        .get_request_timeout = get_request_timeout, .set_request_timeout =
                set_request_timeout, .send_resolver_message =
                send_resolver_response, };

typedef struct sv_resolver_message {
    uint32_t xid;
    uint16_t type;

    atomic_t ref_count;

    uint16_t retries;
    uint16_t message_len;
    uint64_t req_time;
    uint64_t exp_time;
    struct sv_control_header* message;
    resolver_message_callback callback;
} resolver_message;

/* run a single client and single rpc server expiration task - using the min expire timer */
/* TODO - clean up the arrays at some point?*/
struct rpc_expire_set {
    GPtrArray* rpc_list;
    uint32_t min_expiry;
    uint64_t expiration;
    task_handle_t task_handle;
    task_mutex mutex;
    void (*expire_requests)(struct sv_resolver_rpc* bm, uint64_t curtime,
            struct rpc_expire_set* eset);
};

static int handle_request_packet(struct sv_resolver_rpc* bm,
        struct sv_control_header* message, size_t len);

static int handle_response_packet(struct sv_resolver_rpc* bm,
        struct sv_control_header* message, size_t len);

static int resolver_client_callback(void* target, const void* message,
        size_t len);
static int resolver_server_callback(void* target, const void* message,
        size_t len);
static void resolver_message_decref(resolver_message* message);

static void expire_requests(void* data);

static void expire_client_requests(struct sv_resolver_rpc* bm,
        uint64_t curtime, struct rpc_expire_set* eset);
static void expire_server_requests(struct sv_resolver_rpc* bm,
        uint64_t curtime, struct rpc_expire_set* eset);

static struct rpc_expire_set client_expiry = { .rpc_list = NULL, .min_expiry =
        UINT_MAX, .expiration = 0, .task_handle = 0, .mutex =
        TASK_MUTEX_INITIALIZER, .expire_requests = expire_client_requests };

static struct rpc_expire_set server_expiry = { .rpc_list = NULL, .min_expiry =
        UINT_MAX, .expiration = 0, .task_handle = 0, .mutex =
        TASK_MUTEX_INITIALIZER, .expire_requests = expire_server_requests };

static void schedule_expire_timer(struct rpc_expire_set* eset,
        uint64_t expiration) {
    assert(eset);
    task_mutex_lock(&eset->mutex);

    if (expiration < eset->expiration && eset->rpc_list->len > 0) {
        eset->expiration = expiration;
        struct timeval curtime = { 0, 0 };
        expiration = expiration - get_current_time_ms();
        curtime.tv_sec = expiration / 1000;
        curtime.tv_usec = (expiration % 1000) * 1000;
        /*also reschedules */
        eset->task_handle = add_timer_task(eset, expire_requests, &curtime);
    }

    task_mutex_unlock(&eset->mutex);
}
//static void cancel_expire_timer(struct rpc_expire_set* eset) {
//    assert(eset);
//    task_mutex_lock(&eset->mutex);
//    remove_timer_task(eset->task_handle);
//    task_mutex_unlock(&eset->mutex);
//}

static void register_resolver_rpc(struct sv_resolver_rpc* bm,
        struct rpc_expire_set* eset) {
    assert(bm && eset);

    task_mutex_lock(&eset->mutex);

    if (bm->request_timeout < eset->min_expiry) {
        eset->min_expiry = bm->request_timeout;
    }

    if (eset->rpc_list == NULL) {
        eset->rpc_list = g_ptr_array_sized_new(5);
    }

    g_ptr_array_add(eset->rpc_list, bm);

    task_mutex_unlock(&eset->mutex);
}

static void unregister_resolver_rpc(struct sv_resolver_rpc* bm,
        struct rpc_expire_set* eset) {
    assert(bm && eset);

    task_mutex_lock(&eset->mutex);

    uint32_t old_min_expiry = eset->min_expiry;

    if (bm->request_timeout == eset->min_expiry) {
        eset->min_expiry = UINT_MAX;
    }
    struct sv_resolver_rpc* rbm;
    int i = 0;
    for (; i < eset->rpc_list->len; i++) {
        rbm = g_ptr_array_index(eset->rpc_list, i);

        if (bm == rbm) {
            g_ptr_array_remove_index_fast(eset->rpc_list, i);
            bm = NULL;
            if (old_min_expiry == eset->min_expiry) {
                break;
            }
        } else if (old_min_expiry == eset->min_expiry) {
            if (bm == NULL) {
                break;
            }
        } else if (rbm->request_timeout < eset->min_expiry) {
            eset->min_expiry = rbm->request_timeout;
        }
    }

    if (eset->rpc_list->len == 0) {
        remove_timer_task(eset->task_handle);
    }

    task_mutex_unlock(&eset->mutex);
}

int create_resolver_rpc(struct sockaddr_sv* local_resolver,
        struct sv_instance_addr* remote_resolver, uint16_t max_retry,
        uint16_t request_timeout, resolver_message_callback* cb,
        resolver_rpc* messaging) {
    /* if cb is null, then this is a client rpc object, otherwise, it's a server rpc */
    struct sv_resolver_rpc* bm = (struct sv_resolver_rpc*) malloc(sizeof(*bm));

    if (bm == NULL) {
        /* TODO */LOG_ERR("Could not allocate resolver rpc memory!");
        return -1;
    }

    bzero(bm, sizeof(*bm));

    bm->max_retry = max_retry;

    if (request_timeout > 0) {
        bm->request_timeout = request_timeout;
    } else if (cb == NULL) {
        bm->request_timeout = CLIENT_REQUEST_TIMEOUT;
    } else {
        bm->request_timeout = SERVER_REQUEST_TIMEOUT;
    }

    /* TODO hardcoded to use udp (unconnected) datagrams - should be a way to set/change it? */
    message_channel_callback mcb;
    mcb.target = bm;

    if (cb) {
        mcb.recv_message = resolver_server_callback;
    } else {
        mcb.recv_message = resolver_client_callback;
    }

    /*note that the channel can/should be shared between server/client for a given remote peer */
    if (create_udp_message_channel(local_resolver, remote_resolver, 0, &mcb,
            &bm->channel)) {
        LOG_ERR("Could not create resolver rpc - message channel error\n");
        return -1;
    }

    messaging->target = bm;

    if (cb) {
        bm->callback = *cb;
        messaging->interface = &server_rpc_interface;
    } else {
        messaging->interface = &client_rpc_interface;
    }
    return 0;
}

/*hash table helper functions for destroying (freeing) key (xid) and value (resolver_message) */
//static void destroy_message(void* data) {
//    if(data == NULL) {
//        return;
//    }
//
//    resolver_message* message = (resolver_message*) data;
//
//    resolver_message_decref(message);
//}

static int initialize(void* messenger) {

    assert(messenger);

    if (messenger == NULL) {
        LOG_ERR("Cannot initialize null resolver rpc!");
        return -1;
    }

    struct sv_resolver_rpc* bm = (struct sv_resolver_rpc*) messenger;

    //allocate the response/request maps
    task_mutex_init(&bm->req_mutex);

    bm->rpc_request_map = g_hash_table_new_full(g_int_hash, g_int_equal,
            destroy_int_key, NULL);
    bm->channel.interface->initialize(bm->channel.target);

    if (bm->callback.target) {
        register_resolver_rpc(bm, &server_expiry);
    } else {
        register_resolver_rpc(bm, &client_expiry);
    }

    return 0;
}

static void start(void* messenger) {
    assert(messenger);

    struct sv_resolver_rpc* bm = (struct sv_resolver_rpc*) messenger;
    bm->channel.interface->start(bm->channel.target);
}

static void stop(void* messenger) {
    assert(messenger);

    struct sv_resolver_rpc* bm = (struct sv_resolver_rpc*) messenger;
    bm->channel.interface->stop(bm->channel.target);
}

static int finalize(void* messenger) {
    assert(messenger);

    if (messenger == NULL) {
        LOG_ERR("Cannot finalize null resolver rpc!");
        return -1;
    }

    struct sv_resolver_rpc* bm = (struct sv_resolver_rpc*) messenger;

    if (bm->channel.target) {
        message_channel_callback cb;
        cb.target = messenger;

        if (bm->callback.target) {
            cb.recv_message = resolver_server_callback;
        } else {
            cb.recv_message = resolver_client_callback;
        }

        /*TODO in a generic message channel API, register/unregister callback should
         * probably should include message routing rules as well
         */
        bm->channel.interface->unregister_callback(bm->channel.target, &cb);

        if (bm->channel.interface->get_callback_count(bm->channel.target) == 0) {
            bm->channel.interface->finalize(bm->channel.target);
            free(bm->channel.target);
        }

        bm->channel.target = NULL;
    }

    if (bm->rpc_request_map != NULL) {
        g_hash_table_destroy(bm->rpc_request_map);
        //free(bm->rpc_request_map);
        bm->rpc_request_map = NULL;
    }

    if (bm->callback.target) {
        unregister_resolver_rpc(bm, &server_expiry);
    } else {
        unregister_resolver_rpc(bm, &client_expiry);
    }

    task_mutex_destroy(&bm->req_mutex);
    return 0;
}

static int resolver_message_initialize(resolver_message* message) {
    assert(message);
    if (message->message_len > 0) {
        /*allocate the message buffer for received messages */
        message->message = (struct sv_control_header*) malloc(
                message->message_len);
        /* TODO - mem check?*/
    }
    return 0;
}

static int resolver_message_finalize(resolver_message* message) {
    assert(message);

    /* free the message if any */
    if (message->message) {
        free(message->message);
        message->message = NULL;
    }
    return 0;
}

static void resolver_message_decref(resolver_message* message) {
    int refcount = atomic_sub_return(1, &message->ref_count);
    if (refcount == 0) {
        resolver_message_finalize(message);
        free(message);
    }
}

static void expire_requests(void* data) {
    struct rpc_expire_set* eset = (struct rpc_expire_set*) data;
    assert(eset && eset->rpc_list);
    task_mutex_lock(&eset->mutex);
    eset->expiration = 0;

    struct sv_resolver_rpc* bm;

    int i = 0;
    for (; i < eset->rpc_list->len; i++) {

        bm = g_ptr_array_index(eset->rpc_list, i);

        eset->expire_requests(bm, get_current_time_ms(), eset);
    }

    if (eset->expiration > 0) {
        //reschedule
        struct timeval curtime = { 0, 0 };
        curtime.tv_sec = eset->expiration / 1000;
        curtime.tv_usec = (eset->expiration % 1000) * 1000;
        //task_sleep(&curtime);
        add_timer_task(eset, expire_requests, &curtime);
    }

    task_mutex_unlock(&eset->mutex);
}

static void expire_server_requests(struct sv_resolver_rpc* bm,
        uint64_t curtime, struct rpc_expire_set* eset) {
    task_mutex_lock(&bm->req_mutex);

    if (bm->outstanding_requests == 0) {
        goto out;
    }

    int count = 0;

    GHashTableIter iter;
    g_hash_table_iter_init(&iter, bm->rpc_request_map);
    uint32_t* key;
    resolver_message* message;

    //host request lists are removed only when a host leave/timeout event is encountered
    while (g_hash_table_iter_next(&iter, (void**) &key, (void**) &message)) {
        if (message->exp_time <= curtime) {
            g_hash_table_iter_remove(&iter);
            count++;
            bm->outstanding_requests--;

        }
    }

    if (count > 0) {
        LOG_DBG ("Expired %i stale rpc entries", count);
    }

    out: if (bm->outstanding_requests > 0 && eset->expiration == 0) {
        eset->expiration = curtime + eset->min_expiry * 1000;
    }
    task_mutex_unlock(&bm->req_mutex);
}

static void expire_client_requests(struct sv_resolver_rpc* bm,
        uint64_t curtime, struct rpc_expire_set* eset) {
    task_mutex_lock(&bm->req_mutex);

    resolver_message* message = NULL;
    uint32_t* key;

    int count = 0;
    int res = 0;

    GPtrArray* resend = g_ptr_array_new();
    uint64_t mintime = curtime + bm->request_timeout * 1000;

    if (bm->outstanding_requests == 0) {
        goto out;
    }

    GHashTableIter iter;
    g_hash_table_iter_init(&iter, bm->rpc_request_map);

    int len;

    while (g_hash_table_iter_next(&iter, (void**) &key, (void**) &message)) {

        //VLOG_DBG(lg, "Examine rpc entry: %u with exp time: %llu.%llu", req->request_id, req->exp_time / 1000, req->exp_time % 1000);
        if (message->exp_time <= curtime) {
            if (message->retries >= bm->max_retry) {

                //VLOG_DBG(lg,"Request %u timed out!", req->request_id);

                //retried the request the maximum # of times - fail the request and trigger a request fail event
                if (message->message != NULL) {

                    //VLOG_DBG(lg, "Full scaffold control request hex data: %s", to_string(req->data->data(), req->data->size()).c_str());
                    /* note this under lock */
                    message->callback.resolver_message_cb(
                            message->callback.target,
                            SV_TIMEOUT,
                            message->message,
                            message->message_len,
                            (struct sv_instance_addr*) bm->channel.interface->get_peer_address(
                                    bm->channel.target, &len));
                }

                //deletes messenger data here!
                //any threading/concurrency issues?
                g_hash_table_iter_remove(&iter);

                message = NULL;
                bm->outstanding_requests--;
            } else {
                count++;
                //retry the request
                message->retries++;
                message->exp_time = curtime + bm->request_timeout;
                g_ptr_array_add(resend, message);

            }
        }

        if (message) {
            if (mintime > message->exp_time) {
                mintime = message->exp_time;
            }

        }
    }

    out:

    if (bm->outstanding_requests > 0 && (eset->expiration == 0
            || eset->expiration > mintime)) {
        /* set it */
        eset->expiration = mintime;
    }

    task_mutex_unlock(&bm->req_mutex);

    /* send the messages */
    int i = 0;
    for (; i < resend->len; i++) {
        message = (resolver_message*) g_ptr_array_index(resend, i);
        res = bm->channel.interface->send_message(bm->channel.target,
                message->message, message->message_len);
        if (res) {
            LOG_ERR("Error on message send! %s", strerror(errno));
        }
    }
    LOG_DBG("Re-issued %i rpc requests at: %llu mintime: %llu", count, curtime, mintime);

    g_ptr_array_free(resend, TRUE);
}

//const std::string ControllerInterface::to_string(uint8_t* bytes, int len) const {
//    std::string str("<bytes:");
//
//    char bytestr[3];
//
//    for(int i = 0; i < len; i++) {
//        bzero(bytestr, 3);
//        sprintf(bytestr, "%.2X", bytes[i]);
//        str += bytestr;
//
//        if( i % 16 == 15) {
//            str += "\n";
//        }
//        else if( i % 2 == 1) {
//            str += " ";
//        }
//    }
//    str += ">";
//
//    return str;
//}

//TODO - might want to auto ref-count the message and allocate the message buffers in slabs..
static int resolver_client_callback(void* target, const void* message,
        size_t len) {
    return handle_response_packet((struct sv_resolver_rpc*) target,
            (struct sv_control_header*) message, len);
}

static int resolver_server_callback(void* target, const void* message,
        size_t len) {
    return handle_request_packet((struct sv_resolver_rpc*) target,
            (struct sv_control_header*) message, len);
}

static int check_resolver_message(struct sv_resolver_rpc* bm,
        struct sv_control_header* message, size_t len) {
    /* length and type should be verified */

    //uint64_t ctime = get_current_time_ms();
    uint16_t mlen = ntohs(message->length);

    //sanity check the length
    if (len != mlen) {
        LOG_ERR("Invalid serval message length: %i != %u", len, mlen);
        //drop the packet
        return 0;
    }

    if (message->version != SV_VERSION) {
        LOG_ERR("Invalid serval version: %u", message->version);
        return 0;
    }

    //check the protocol version
    uint16_t type = ntohs(message->type);

    /*VLOG_DBG(lg, "control header: %u join: %u joinrep: %u leave: %u refresh: %u refreshrep: %u register: %u registerrep: %u unregister: %u unregisterrep: %u error: %u",
     sizeof(sc_control_header), sizeof(sc_host_join_request), sizeof(sc_host_join_reply),
     sizeof(sc_host_leave), sizeof(sc_refresh_request), sizeof(sc_refresh_reply),
     sizeof(sc_object_register_request), sizeof(sc_object_register_reply),
     sizeof(sc_object_unregister_request), sizeof(sc_object_unregister_reply), sizeof(sc_op_error));*/

    //VLOG_DBG(lg, "mac addr size: %u", sizeof(macaddr));
    //VLOG_DBG(lg, "Handling control packet: %s", header->to_string().c_str());

    if (type < SV_DISCOVER_MESSAGE || type > SV_ERROR) {
        LOG_ERR("Invalid control packet. Unrecognized message type: %u", type);
        return 0;
    }

    //uint32_t xid = ntohl(message->xid);
    //int rtype = RM_UNKNOWN;
    //sanity check the messages

    switch (type) {
    case SV_DISCOVER_MESSAGE:
    case SV_DISAPPEAR_MESSAGE:
        //VLOG_DBG(lg, "Created leave event!");
        //basic service router "ping"
    case SV_ECHO_REQUEST:
        return bm->callback.target != NULL;
    case SV_ECHO_REPLY:
        return bm->callback.target == NULL;
    case SV_REGISTER_REQUEST:
    case SV_UNREGISTER_REQUEST:
        //service update (load and meta/stat info)
    case SV_UPDATE_REQUEST:
    case SV_UPDATE_MESSAGE:
    case SV_QUERY_REQUEST:
        return bm->callback.target != NULL;
    case SV_QUERY_REPLY:
    case SV_ACK:
        return bm->callback.target == NULL;
    default:
        //error
        LOG_ERR("Invalid control packet. Message type: %u.", type);
        return 0;
    }

    return 0;
}
static void resolver_message_incref(resolver_message* rmessage) {
    atomic_inc(&rmessage->ref_count);
}

static int handle_request_packet(struct sv_resolver_rpc* bm,
        struct sv_control_header* message, size_t len) {
    assert(bm && message);
    int retval = 0;

    if (!check_resolver_message(bm, message, len)) {
        //LOG_ERR("Client response cannot be handled by a server rpc! %u", type);
        return -1;
    }

    uint32_t xid = ntohl(message->xid);

    task_mutex_lock(&bm->req_mutex);

    bm->last_remote_access = get_current_time_ms();
    resolver_message* rmessage = (resolver_message*) g_hash_table_lookup(
            bm->rpc_request_map, &xid);

    if (rmessage) {
        /* existing request - send response if it exists
         * need to ensure the message is not deleted from under us
         */

        resolver_message_incref(rmessage);
        task_mutex_unlock(&bm->req_mutex);

        if (rmessage->message) {
            retval = bm->channel.interface->send_message(bm->channel.target,
                    rmessage->message, rmessage->message_len);
        } else {
            LOG_DBG("No response for existing request generated yet");
            retval = -1;
        }

        resolver_message_decref(rmessage);
    } else {
        if (bm->callback.target == NULL) {
            LOG_ERR("No server callback specified, dropping message: %u", xid);
            retval = -1;
            goto unlockout;
        }
        int alen;
        uint16_t type = ntohs(message->type);

        if (type == SV_UPDATE_REQUEST || type == SV_REGISTER_REQUEST || type
                == SV_UNREGISTER_REQUEST || type == SV_QUERY_REQUEST) {
            /* new request */LOG_DBG("Handling serval protocol request: %u", type);
            rmessage = (resolver_message*) malloc(sizeof(resolver_message));

            //assert?
            if (rmessage == NULL) {
                LOG_ERR("Could not allocate a resolver_message - dropping request");
                retval = -1;
                goto unlockout;
            }
            bzero(rmessage, sizeof(*rmessage));
            /* rmessage->message_len = len; */
            rmessage->xid = xid;
            rmessage->req_time = bm->last_remote_access;
            rmessage->exp_time = bm->last_remote_access + bm->request_timeout
                    * 1000;

            resolver_message_initialize(rmessage);

            /* memcpy(rmessage->message, message, len); */

            uint32_t * key = (uint32_t*) malloc(sizeof(uint32_t));
            *key = xid;

            g_hash_table_insert(bm->rpc_request_map, key, rmessage);

            resolver_message_incref(rmessage);

            if (bm->outstanding_requests == 0) {
                schedule_expire_timer(&server_expiry, rmessage->exp_time);
            }

            bm->outstanding_requests++;
        } else {
            LOG_DBG("Handling serval protocol message: %u", type);
        }

        task_mutex_unlock(&bm->req_mutex);

        /* another option is to push this onto the task queue for async handling
         * which could be determined adaptively based on resptime - would require
         * copying the message body
         */
        bm->callback.resolver_message_cb(
                bm->callback.target,
                type,
                message,
                len,
                (struct sv_instance_addr*) bm->channel.interface->get_peer_address(
                        bm->channel.target, &alen));
    }
    goto out;
    unlockout: task_mutex_unlock(&bm->req_mutex);
    out: return retval;
}

static int handle_response_packet(struct sv_resolver_rpc* bm,
        struct sv_control_header* message, size_t len) {
    assert(bm && message);
    resolver_message* rmessage;
    int retval = 0;

    if (!check_resolver_message(bm, message, len)) {
        //LOG_ERR("Server request cannot be handled by a client rpc! %u", type);
        return -1;
    }

    //        case RM_UNKNOWN:
    //
    //            task_mutex_lock(&bm->req_mutex);
    //            rmessage = (resolver_message*) g_hash_table_lookup(bm->rpc_request_map,
    //                    (const void*) &xid);
    //            if(rmessage) {
    //                if(!g_hash_table_remove(bm->rpc_request_map, &xid)) {
    //                    LOG_ERR("Remove error on response for rpc request: %u", xid);
    //                } else {
    //                    bm->outstanding_requests--;
    //                }
    //            }
    //            task_mutex_unlock(&bm->req_mutex);
    //
    //            if(rmessage) {
    //                //it's a response - check for a callback
    //                if(rmessage->callback.target) {
    //                    rmessage->callback.resolver_message_cb(rmessage.callback.target, type, message,
    //                            len);
    //                } else if(bm->callback.target) {
    //                    bm->callback.resolver_message_cb(bm.callback.target, type, message, len);
    //                } else {
    //                    LOG_ERR("No default response callback defined - dropping rpc response: %u", xid);
    //                }
    //                resolver_message_fini(rmessage);
    //                free(rmessage);
    //
    //                retval = -1;
    //                break;
    //            }
    task_mutex_lock(&bm->req_mutex);
    bm->last_remote_access = get_current_time_ms();

    uint32_t xid = ntohl(message->xid);
    int alen;
    rmessage = (resolver_message*) g_hash_table_lookup(bm->rpc_request_map,
            &xid);

    if (rmessage) {
        if (!g_hash_table_remove(bm->rpc_request_map, &rmessage->xid)) {
            LOG_ERR("Remove error on response for rpc request: %u", rmessage->xid);
        }

        bm->outstanding_requests--;
        task_mutex_unlock(&bm->req_mutex);

        if (rmessage->callback.target) {
            /* another option is to push this onto the task queue for async handling
             * which could be determined adaptively based on resptime - would require
             * copying the message body
             */
            rmessage->callback.resolver_message_cb(
                    rmessage->callback.target,
                    message->type,
                    message,
                    len,
                    (struct sv_instance_addr*) bm->channel.interface->get_peer_address(
                            bm->channel.target, &alen));
        } else {
            LOG_ERR("No default response callback defined - dropping rpc response: %u", xid);
            retval = -1;
        }

    } else {
        LOG_ERR("No request matching response message: %u", xid);
        retval = -1;
    }

    return retval;
}

static int send_resolver_response(void* target, uint32_t xid,
        struct sv_control_header* response, size_t len,
        resolver_message_callback* rm_cb) {
    assert(target);

    struct sv_resolver_rpc* bm = (struct sv_resolver_rpc*) target;

    if (response == NULL) {
        return -1;
    }

    resolver_message* rmessage = NULL;
    int retval = 0;

    uint16_t type = ntohs(response->type);

    task_mutex_lock(&bm->req_mutex);

    rmessage = g_hash_table_lookup(bm->rpc_request_map, (const void*) &xid);

    if (rmessage == NULL) {
        if (type != SV_UPDATE_MESSAGE) {
            //error - response to non-existent request
            LOG_ERR("No request entry found for %u xid, message type: %u", xid, type);
            retval = -1;
        }
        goto unlock;
    }

    if (rmessage->message) {
        /* response already exists - another error*/LOG_ERR("A response has already been sent for %u xid, type: %u", xid, type);
        retval = -1;
        goto unlock;
    }

    uint64_t ctime = get_current_time_ms();

    rmessage->message = response;
    rmessage->message_len = len;
    rmessage->exp_time = ctime + bm->request_timeout * 1000;

    unlock: task_mutex_unlock(&bm->req_mutex);

    if (retval) {
        return retval;
    }

    //uint16_t rtype = ntohs(response->type);
    //stat_map[treq->request_type].add_sample(ctime - treq->req_time, rtype != SC_ERROR);

    //treq->exp_time = curtime.tv_sec * 1000 + rpc_expire_timeout * 1000;
    return bm->channel.interface->send_message(bm->channel.target, response,
            len);
}

static int send_resolver_request(void* target, uint32_t xid,
        struct sv_control_header* request, size_t len,
        resolver_message_callback* rm_cb) {
    assert(target);
    struct sv_resolver_rpc* bm = (struct sv_resolver_rpc*) target;

    if (request == NULL) {
        LOG_ERR("Cannot send a null request");
        return -1;
    }

    resolver_message* rmessage = NULL;

    int retval = 0;
    uint8_t type = request->type;
    if (!(type == SV_DISCOVER_MESSAGE || type == SV_UPDATE_MESSAGE)) {

        task_mutex_lock(&bm->req_mutex);

        if ((rmessage = g_hash_table_lookup(bm->rpc_request_map,
                (const void*) &xid))) {
            //error - response to non-existent request
            LOG_ERR("Duplicate request entry found for xid %u", xid);
            retval = -1;
            goto unlock;
        }

        rmessage = (resolver_message*) malloc(sizeof(resolver_message));

        //assert?
        if (rmessage == NULL) {
            LOG_ERR("Could not allocate memory for request resolver message");
            retval = -1;
            goto unlock;
        }

        uint64_t ctime = get_current_time_ms();

        rmessage->xid = xid;
        rmessage->req_time = ctime;
        rmessage->exp_time = ctime + bm->request_timeout * 1000;

        resolver_message_initialize(rmessage);

        rmessage->message = request;
        rmessage->message_len = len;

        if (rm_cb) {
            rmessage->callback.target = rm_cb->target;
            rmessage->callback.resolver_message_cb = rm_cb->resolver_message_cb;
        }

        uint32_t* key = (uint32_t*) malloc(sizeof(uint32_t));
        *key = xid;
        g_hash_table_insert(bm->rpc_request_map, key, rmessage);
        resolver_message_incref(rmessage);

        //schedule the expire timer if not previously scheduled
        if (bm->outstanding_requests == 0) {
            schedule_expire_timer(&client_expiry, rmessage->exp_time);
        }

        bm->outstanding_requests++;

        unlock: task_mutex_unlock(&bm->req_mutex);
    }
    //    VLOG_DBG(
    //            lg,
    //            "Inserted a new RPC request entry for entity %llu transID %u request list size: %u exp time: %llu",
    //            host.eid, id, rlist->size(), treq->exp_time);


    //request with id to host exists - rely on retry!
    return retval;
}

static uint32_t get_outstanding_requests(void* resm) {
    assert(resm);
    struct sv_resolver_rpc* bm = (struct sv_resolver_rpc*) resm;
    uint32_t oreq;
    task_mutex_lock(&bm->req_mutex);
    oreq = bm->outstanding_requests;
    task_mutex_unlock(&bm->req_mutex);
    return oreq;
}

static uint16_t get_max_retry(void* resm) {
    assert(resm);
    struct sv_resolver_rpc* bm = (struct sv_resolver_rpc*) resm;
    uint16_t retry;
    task_mutex_lock(&bm->req_mutex);
    retry = bm->max_retry;
    task_mutex_unlock(&bm->req_mutex);
    return retry;
}
static void set_max_retry(void* resm, uint16_t retry) {
    assert(resm);
    struct sv_resolver_rpc* bm = (struct sv_resolver_rpc*) resm;
    if (retry > 0) {
        task_mutex_lock(&bm->req_mutex);
        bm->max_retry = retry;
        task_mutex_unlock(&bm->req_mutex);
    }

}
static uint16_t get_request_timeout(void* resm) {
    assert(resm);
    struct sv_resolver_rpc* bm = (struct sv_resolver_rpc*) resm;
    uint32_t retry;
    task_mutex_lock(&bm->req_mutex);
    retry = bm->request_timeout;
    task_mutex_unlock(&bm->req_mutex);
    return retry;
}

static void set_request_timeout(void* resm, uint16_t timeout) {
    assert(resm);
    struct sv_resolver_rpc* bm = (struct sv_resolver_rpc*) resm;
    if (timeout > 0) {
        task_mutex_lock(&bm->req_mutex);
        bm->request_timeout = timeout;
        task_mutex_unlock(&bm->req_mutex);
    }
}

void resolver_rpc_set_peer(struct sv_resolver_rpc* bm,
        struct sv_instance_addr* peer_addr) {
    assert(bm);
    if (peer_addr == NULL) {
        return;
    }

    /* only place to lock both locks? TODO - going to be hard to debug with coroutines...*/task_mutex_lock(&bm->req_mutex);
    bm->channel.interface->set_peer_address(bm->channel.target,
            (struct sockaddr*) peer_addr, sizeof(*peer_addr));
    task_mutex_lock(&bm->req_mutex);
}

const struct sv_instance_addr* resolver_rpc_get_peer(struct sv_resolver_rpc* bm) {
    assert(bm);
    const struct sv_instance_addr* peer;
    task_mutex_lock(&bm->req_mutex);
    int len;
    peer = (struct sv_instance_addr*) bm->channel.interface->get_peer_address(
            bm->channel.target, &len);
    task_mutex_lock(&bm->req_mutex);
    return peer;
}

int resolver_rpc_get_max_message_size(struct sv_resolver_rpc* bm) {
    assert(bm);

    task_mutex_lock(&bm->req_mutex);
    int max;
    max = bm->channel.interface->get_max_message_size(bm->channel.target);
    task_mutex_lock(&bm->req_mutex);
    return max;
}

uint64_t resolver_rpc_get_last_remote_access(struct sv_resolver_rpc* bm) {
    assert(bm);
    task_mutex_lock(&bm->req_mutex);
    uint64_t lra = bm->last_remote_access;
    task_mutex_lock(&bm->req_mutex);
    return lra;
}
