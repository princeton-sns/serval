/*
 * local_resolver.c
 *
 *  Created on: Feb 19, 2011
 *      Author: daveds
 */

#include "resolver.h"
#include "resolver_base.h"
#include "resolution_path.h"
#include "time_util.h"
#include "service_util.h"
#include "service_table.h"
#include "message_channel.h"
#include "task.h"
#include "debug.h"
#include <glib.h>
#include <assert.h>

#define EXPIRATION_INTERVAL 5
#define DISCOVERY_INTERVAL 30
#define DISCOVERY_COOLDOWN 5

struct sv_local_resolver {
    struct sv_base_service_resolver resolver;
    uint64_t start_time;
    //rtt estimate? - proximity?

    /* modules:
     * discovery/status
     * registration
     * resolution
     *
     * peers-neighbor - table
     *  resolution view - what do I know, what do others know about me/local scope
     * service-table - by scope? host, local, (remote?)
     */

    uint16_t echo_interval;
    uint16_t disc_interval;
    uint16_t expire_interval;

    task_handle_t echo_task;
    task_handle_t discover_task;
    task_handle_t expire_task;

    service_resolver_callback echo_callback;
    resolution_path_callback path_callback;
    task_mutex peer_mutex;
    GHashTable* peer_table;

    task_rwlock res_lock;
    struct sv_service_table resolution_table;

    service_resolver* default_peer;
    resolution_path* rpath;
//service_resolver* self;
};

struct peer_info {
    service_resolver* peer;
    int poking;
    /* track per-peer info */
    uint64_t last_discovery;
    uint32_t disc_cooldown;
    uint32_t disc_count;

};

struct peer_cb_info {
    struct sv_local_resolver* resolver;
    struct peer_info* pinfo;
    service_resolver_callback cb;
};

struct register_cb_info {
    struct sv_local_resolver* resolver;
    struct peer_info* pinfo;
    GArray* svc_list;
    struct net_addr* address;
    int type;
    service_resolver_callback cb;
};

static int local_initialize(service_resolver* resolver);
static void local_stop(service_resolver* resolver);
static void local_start(service_resolver* resolver);

static int local_finalize(service_resolver* resolver);
static uint32_t local_get_uptime(service_resolver* resolver);
static void local_set_uptime(service_resolver* resolver, uint32_t uptime);

static void local_set_capabilities(service_resolver*resolver, uint32_t capabilities);

static int local_peer_discovered(service_resolver* resolver, service_resolver* peer, uint16_t type);
static int
local_peer_disappeared(service_resolver* resolver, service_resolver* peer, uint16_t type);

static int local_register_services(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address, uint32_t ttl);
static int local_register_services_async(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address, uint32_t ttl,
        service_resolver_callback* callback);

static int local_unregister_services(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address);
static int local_unregister_services_async(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address,
        service_resolver_callback* callback);

static int local_query_services(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc);
static int local_query_services_async(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, service_resolver_callback* callback);

static int local_get_service_updates(service_resolver* resolver, service_resolver* peer,
        uint16_t type, struct service_desc*, size_t num_svc, stat_response* responses);
static int local_get_service_updates_async(service_resolver* resolver, service_resolver* peer,
        uint16_t type, struct service_desc*, size_t num_svc, stat_response* responses,
        service_resolver_callback* callback);

static int local_update_services(service_resolver* resolver, service_resolver* peer, uint16_t type,
        stat_response* responses);

static int local_resolve_service(service_resolver* resolver, service_resolver* peer,
        struct service_desc* service, struct net_addr* address);
static int
        local_resolve_service_async(service_resolver* resolver, service_resolver* peer,
                struct service_desc* service, struct net_addr* address,
                service_resolver_callback* callback);

static int local_poke_resolver(service_resolver* resolver, service_resolver* peer, uint32_t count);
static int local_poke_resolver_async(service_resolver* resolver, service_resolver* peer,
        uint32_t count, service_resolver_callback* callback);

static void local_incref(service_resolver* resolver);
static void local_decref(service_resolver* resolver);

static service_resolver* local_get_peer(service_resolver* resolver, struct service_id* peer_id);

static int local_has_peer(service_resolver* resolver, struct service_id* peer_id);
static int local_get_peer_count(service_resolver* resolver);
static void local_clear_peers(service_resolver* resolver);

static struct sv_resolver_interface local_resolver_interface = {
//eh?
        .initialize = local_initialize,
        .start = local_start,
        .stop = local_stop,
        .finalize = local_finalize,
        .incref = local_incref,
        .decref = local_decref,

        .get_uptime = local_get_uptime,
        .set_uptime = local_set_uptime,
        .set_address = base_resolver_set_address,
        .set_capabilities = local_set_capabilities,
        .get_peer = local_get_peer,
        .has_peer = local_has_peer,
        .get_peer_count = local_get_peer_count,
        .clear_peers = local_clear_peers,
        .peer_discovered = local_peer_discovered,
        .peer_disappeared = local_peer_disappeared,
        .register_services = local_register_services,
        //zero signifies error, anything else is a xid
        .register_services_async = local_register_services_async,
        .unregister_services = local_unregister_services,
        .unregister_services_async = local_unregister_services_async,

        .query_services = local_query_services,
        .query_services_async = local_query_services_async,

        .update_services = local_update_services,

        .get_service_updates = local_get_service_updates,
        .get_service_updates_async = local_get_service_updates_async,
        //resolve multiple services?
        .resolve_service = local_resolve_service,
        .resolve_service_async = local_resolve_service_async,

        .poke_resolver = local_poke_resolver,
        .poke_resolver_async = local_poke_resolver_async };

static int notify_peer_registration(struct sv_local_resolver* lres, service_resolver* peer,
        GArray* svc_list, struct net_addr* address, uint32_t ttl, int type);
static void purge_peer_resolution(struct sv_local_resolver*lres, service_resolver* peer,
        struct sockaddr_sv* sdesc);

static service_resolver* local_get_peer(service_resolver* resolver, struct service_id* peer_id) {
    assert(resolver);

    struct sv_local_resolver* lres = (struct sv_local_resolver*) resolver;

    task_mutex_lock(&lres->peer_mutex);

    struct peer_info * peer = (struct peer_info*) g_hash_table_lookup(lres->peer_table, peer_id);

    task_mutex_unlock(&lres->peer_mutex);
    return peer->peer;
}

static int local_has_peer(service_resolver* resolver, struct service_id* peer_id) {
    assert(resolver);

    struct sv_local_resolver* lres = (struct sv_local_resolver*) resolver;

    task_mutex_lock(&lres->peer_mutex);

    service_resolver* res = (service_resolver*) g_hash_table_lookup(lres->peer_table, peer_id);

    task_mutex_unlock(&lres->peer_mutex);

    return res != NULL;
}

static int local_get_peer_count(service_resolver* resolver) {
    assert(resolver);

    struct sv_local_resolver* lres = (struct sv_local_resolver*) resolver;

    task_mutex_lock(&lres->peer_mutex);

    int size = g_hash_table_size(lres->peer_table);

    task_mutex_unlock(&lres->peer_mutex);
    return size;

}

static void local_clear_peers(service_resolver* resolver) {
    assert(resolver);

    struct sv_local_resolver* lres = (struct sv_local_resolver*) resolver;

    task_mutex_lock(&lres->peer_mutex);

    GHashTableIter iter;
    g_hash_table_iter_init(&iter, lres->peer_table);
    struct peer_info* pinfo;
    service_resolver* peer;
    while(g_hash_table_iter_next(&iter, NULL, (void**) &pinfo)) {
        peer = pinfo->peer;
        peer->interface->incref(peer);

        g_hash_table_iter_remove(&iter);
        /*could be a dangerous lock contention...TODO*/
        task_rwlock_wrlock(&lres->res_lock);
        purge_peer_resolution(lres, peer, NULL);

        if(peer->resolver.relation == RELATION_PARENT) {
            purge_peer_resolution(lres, peer, &peer->resolver.resolver_id);
        }
        task_rwlock_unlock(&lres->res_lock);

        peer->interface->decref(peer);
    }

    task_mutex_unlock(&lres->peer_mutex);

}

static void local_set_capabilities(service_resolver*resolver, uint32_t capabilities) {
    assert(resolver);

    struct sv_local_resolver* lres = (struct sv_local_resolver*) resolver;

    task_rwlock_wrlock(&lres->res_lock);
    lres->rpath->interface->set_capabilities(lres->rpath, capabilities);

    task_rwlock_unlock(&lres->res_lock);
}

static void local_incref(service_resolver* resolver) {
    assert(resolver);
    base_resolver_incref(resolver);

}
static void local_decref(service_resolver* resolver) {
    assert(resolver);
    struct sv_local_resolver* localres = (struct sv_local_resolver*) resolver;

    if(atomic_dec_and_test(&localres->resolver.ref_count)) {
        resolver->interface->finalize(resolver);
        free(resolver);
    }
}

static uint32_t local_get_uptime(service_resolver* resolver) {
    assert(resolver);

    struct sv_local_resolver* lres = (struct sv_local_resolver*) resolver;
    printf("local get uptime: %llu\n", get_current_time_ms());
    uint64_t ctime = get_current_time_ms();

    return (uint32_t) ((ctime - lres->start_time) / 1000);
}

static void local_set_uptime(service_resolver* resolver, uint32_t uptime) {

}

static void purge_peer_resolution(struct sv_local_resolver*lres, service_resolver* peer,
        struct sockaddr_sv* sdesc) {
    /*if the peer is a parent, remove the default resolution*/
    //struct service_reference ref;
    //struct sockaddr_sv* sdesc = &peer->resolver.resolver_id;
    //        bzero(&ref, sizeof(ref));
    //        memcpy(&ref.instance.service, &peer->resolver.resolver_id,
    //                sizeof(struct sockaddr_sv));
    //        memcpy(&ref.instance.address, resolver_get_address(peer, 0),
    //                sizeof(struct net_addr));

    if(sdesc) {
        service_table_remove_service_reference(&lres->resolution_table, sdesc->sv_flags,
                sdesc->sv_prefix_bits, &sdesc->sv_srvid, resolver_get_address(peer, 0), NULL);
    } else {
        struct service_id dummy;
        service_table_remove_service_reference(&lres->resolution_table, 0, 0, &dummy,
                resolver_get_address(peer, 0), NULL);
    }

    struct service_resolution_stat res;
    bzero(&res, sizeof(res));

    if(sdesc) {
        res.res.sv_flags = sdesc->sv_flags;
        res.res.sv_prefix_bits = sdesc->sv_prefix_bits;
        memcpy(&res.res.srvid, &sdesc->sv_srvid, sizeof(struct service_id));
    }

    memcpy(&res.res.address, resolver_get_address(peer, 0), sizeof(struct net_addr));

    //init_resolution_from_reference(&res, &ref);

    lres->rpath->interface->remove_resolutions(lres->rpath, &res, 1);

}

/* TODO -start/stop/suspend/resume? */

static void local_echo_callback(service_resolver_callback* cb, int status, void* data) {
    assert(cb);
    struct peer_cb_info* cbinfo = (struct peer_cb_info*) cb->target;

    enum resolver_state pstatus = ACTIVE;
    task_mutex_lock(&cbinfo->resolver->peer_mutex);
    if(status == -SV_TIMEOUT) {
        /* purge the peer */

        g_hash_table_remove(cbinfo->resolver->peer_table,
                &cbinfo->pinfo->peer->resolver.resolver_id.sv_srvid);
        pstatus = UNRESPONSIVE;

    } else if(status == -SV_ERROR) {
        g_hash_table_remove(cbinfo->resolver->peer_table,
                &cbinfo->pinfo->peer->resolver.resolver_id.sv_srvid);
        pstatus = UNRESPONSIVE;
    } else {
        /* all good - last access should already be updated, simply set
         * poking state to off
         */
        cbinfo->pinfo->poking = FALSE;
    }

    task_mutex_unlock(&cbinfo->resolver->peer_mutex);

    if(pstatus > ACTIVE) {
        notify_peer_status_callbacks((service_resolver*) cbinfo->resolver, cbinfo->pinfo->peer,
                pstatus);
    }

    task_rwlock_wrlock(&cbinfo->resolver->res_lock);
    purge_peer_resolution(cbinfo->resolver, cbinfo->pinfo->peer, NULL);

    if(cbinfo->pinfo->peer->resolver.relation == RELATION_PARENT) {
        purge_peer_resolution(cbinfo->resolver, cbinfo->pinfo->peer,
                &cbinfo->pinfo->peer->resolver.resolver_id);
    }
    task_rwlock_unlock(&cbinfo->resolver->res_lock);

    /*decrementing the echo ref*/
    cbinfo->pinfo->peer->interface->decref(cbinfo->pinfo->peer);

    free(cbinfo);
}

/* echo - task to check for liveness */
static void local_echo_task(void* data) {
    if(data == NULL) {
        LOG_ERR("Cannot execute echo task if no resolver specified");
        return;
    }

    struct sv_local_resolver* lres = (struct sv_local_resolver*) data;

    /* iterate through all the peers and if any have not updated within the heart-beat interval,
     * poke them
     */

    uint64_t ctime = get_current_time_ms();
    uint64_t lastup = 0;
    GHashTableIter iter;

    task_mutex_lock(&lres->peer_mutex);

    g_hash_table_iter_init(&iter, lres->peer_table);

    struct peer_info* rinfo = NULL;

    /* these could be added into the peer_info struct, but knowing when to free them would be more difficult */
    struct peer_cb_info* cbinfo = NULL;

    while(g_hash_table_iter_next(&iter, NULL, (void**) &rinfo)) {
        if(rinfo == NULL || rinfo->poking) {
            continue;
        }

        /* last_access is not atomically updated... TODO */
        lastup = rinfo->peer->resolver.last_access;

        if(ctime - lastup > lres->echo_interval) {
            /*count?*/
            rinfo->poking = TRUE;
            rinfo->peer->interface->incref(rinfo->peer);

            cbinfo = (struct peer_cb_info*) malloc(sizeof(*cbinfo));
            cbinfo->pinfo = rinfo;
            cbinfo->resolver = lres;
            cbinfo->cb.target = cbinfo;
            cbinfo->cb.service_resolver_cb = local_echo_callback;

            rinfo->peer->interface->poke_resolver_async(rinfo->peer, &lres->resolver.resolver, 0,
                    &cbinfo->cb);
        }
    }

    if(g_hash_table_size(lres->peer_table) > 0) {
        struct timeval cur;
        cur.tv_sec = lres->echo_interval;
        cur.tv_usec = 0;
        lres->echo_task = add_timer_task(lres, local_echo_task, &cur);
    }

    task_mutex_unlock(&lres->peer_mutex);

}

static void local_expire_task(void* data) {
    /* for the time being the expire task uses a
     * regular expiration interval rather than a ttl priority queue
     * ttl 0 = never expire
     */

    if(data == NULL) {
        LOG_ERR("Cannot execute expire task if no resolver specified");
        return;
    }

    LOG_DBG("Executing expiration task\n");

    uint64_t ctime = get_current_time_ms();
    struct sv_local_resolver* lres = (struct sv_local_resolver*) data;
    int size = 0;

    /*iterate through the service table */
    struct service_table_iter iter;
    service_table_iter_init(&iter, &lres->resolution_table);

    struct service_reference *ref;
    struct service_resolution_stat resolution;
    struct service_desc sdesc;

    GArray* svc_list = NULL;
    GArray* ref_list = g_array_new(FALSE, TRUE, sizeof(resolution));

    task_rwlock_wrlock(&lres->res_lock);

    while(service_table_iter_next(&iter, &ref)) {
        if(ref->ttl == 0) {
            continue;
        }
        if(ref->registered + ref->ttl * 1000 > ctime) {

            //            sres.sv_flags = ref->instance.service.sv_flags;
            //            sres.sv_prefix_bits = ref->instance.service.sv_prefix_bits;
            //            memcpy(&sres.srvid, &ref->instance.service.sv_srvid, sizeof(struct service_id));
            //            memcpy(&sres.address, &ref->instance.address.sin.sin_addr, sizeof(struct net_addr));
            //            sres.priority = ref->priority;
            //            sres.weight = ref->weight;
            //            sres.hard_timeout = ref->hard_timeout;
            //            sres.idle_timeout = ref->idle_timeout;

            bzero(&resolution, sizeof(resolution));
            init_resolution_from_reference(&resolution.res, ref);
            g_array_append_val(ref_list, resolution);

            /* default policy is to not unregister until last */
            if(service_table_iter_reference_count(&iter) == 1) {
                init_description_from_reference(&sdesc, ref);

                if(svc_list == NULL) {
                    svc_list = g_array_new(FALSE, TRUE, sizeof(sdesc));
                    g_array_append_val(svc_list, sdesc);
                } else {
                    g_array_index(svc_list, struct service_desc, 0) = sdesc;
                }

                notify_peer_registration(lres, NULL, svc_list,
                        (struct net_addr*) &ref->instance.address.sin.sin_addr, 0,
                        SV_UNREGISTER_REQUEST);
                g_array_unref(svc_list);
            }

            service_table_iter_remove(&iter, NULL);
        }
    }

    service_table_iter_destroy(&iter);

    if(ref_list->len > 0) {
        lres->rpath->interface->remove_resolutions(lres->rpath,
                (struct service_resolution_stat*) ref_list->data, ref_list->len);
    }
    g_array_free(ref_list, TRUE);

    if(svc_list) {
        g_array_free(svc_list, TRUE);
    }

    size = service_table_size(&lres->resolution_table);

    if(size > 0) {
        struct timeval cur;
        cur.tv_sec = lres->expire_interval;
        cur.tv_usec = 0;
        lres->expire_task = add_timer_task(lres, local_expire_task, &cur);
    }

    task_rwlock_unlock(&lres->res_lock);

}

/* discovery task to find new peers */
static void local_discover_task(void* data) {
    if(data == NULL) {
        LOG_ERR("Cannot execute echo task if no resolver specified");
        return;
    }

    LOG_DBG("Executing discovery task\n");
    struct sv_local_resolver* lres = (struct sv_local_resolver*) data;

    /* default is to find peers on the local segment for now - do not propagate TODO */
    lres->default_peer->interface->peer_discovered(lres->default_peer, &lres->resolver.resolver,
            DISCOVER_NOTIFY);

    struct timeval cur;
    cur.tv_sec = lres->disc_interval;
    cur.tv_usec = 0;
    lres->discover_task = add_timer_task(lres, local_discover_task, &cur);
}

/* peer registration - simply notify all parents
 * if no parents - then notify authoritative
 * */

/* peer unregistration - also notify all parents
 * if no parents then notify authoritative
 * */

static void destroy_peer_info(void* value) {
    if(value == NULL) {
        return;
    }

    struct peer_info* pinfo = (struct peer_info*) value;
    pinfo->peer->interface->decref(pinfo->peer);
    free(pinfo);
}

static int local_handle_path_service_registered(resolution_path_callback* cb,
        struct service_desc* service);
static int local_handle_path_service_unregistered(resolution_path_callback* target,
        struct service_desc* service);
static int local_handle_path_stat_update(resolution_path_callback* target,
        struct service_resolution_stat* res_stats, size_t scount);
static int local_handle_path_resolve_service(resolution_path_callback* target,
        struct service_desc* service, struct net_addr* address);

service_resolver* create_local_service_resolver(struct sockaddr_sv* local, uint32_t capabilities,
        uint32_t capacity, service_resolver* default_res, resolution_path* spath) {
    struct sv_local_resolver* lres = (struct sv_local_resolver*) malloc(sizeof(*lres));

    if(lres == NULL) {
        LOG_ERR("Could not allocate local resolver memory!");
        return NULL;
    }

    bzero(lres, sizeof(*lres));
    init_base_resolver(&lres->resolver);

    memcpy(&lres->resolver.resolver.resolver.resolver_id, local, sizeof(struct sockaddr_sv));

    lres->start_time = get_current_time_ms();

    /*first address specified */
    lres->resolver.resolver.resolver.capabilities = capabilities;
    lres->resolver.resolver.resolver.capacity = capacity;
    lres->resolver.resolver.resolver.relation = RELATION_SELF;

    /* addresses and auth/delegate service_descs added externally */

    //lres->callback.target = lres;
    //lres->callback.resolver_message_cb = local_resolver_message_cb;

    /* the default peer - used for issuing discovery messages
     * note that this resolver now owns the peer
     * */
    lres->disc_interval = DISCOVERY_INTERVAL;
    lres->expire_interval = EXPIRATION_INTERVAL;
    if(default_res) {
        lres->default_peer = default_res;
    }

    lres->path_callback.target = lres;
    lres->path_callback.resolve_service = local_handle_path_resolve_service;
    lres->path_callback.service_registered = local_handle_path_service_registered;
    lres->path_callback.service_unregistered = local_handle_path_service_unregistered;
    lres->path_callback.stat_update = local_handle_path_stat_update;

    if(spath) {
        lres->rpath = spath;
        spath->interface->set_path_callback(spath, &lres->path_callback);
    }

    lres->resolver.resolver.interface = &local_resolver_interface;
    return &lres->resolver.resolver;
}

static int local_handle_path_service_registered(resolution_path_callback* cb,
        struct service_desc* service) {
    assert(cb);
    service_resolver* res = (service_resolver*) cb->target;
    return res->interface->register_services(res, NULL, service, 1, NULL, 0);
}
static int local_handle_path_service_unregistered(resolution_path_callback* cb,
        struct service_desc* service) {
    assert(cb);
    service_resolver* res = (service_resolver*) cb->target;
    return res->interface->unregister_services(res, NULL, service, 1, NULL);
}

static int local_handle_path_stat_update(resolution_path_callback* cb,
        struct service_resolution_stat* res_stats, size_t scount) {
    assert(cb);
    service_resolver* res = (service_resolver*) cb->target;

    stat_response resp;
    resp.count = scount;
    resp.type = SVS_INSTANCE_STATS;
    /*TODO this is rather dangerous to assume - full binary compatibilitye between service_resolution_stat == sv_instance_stats*/
    resp.data = (uint8_t*) res_stats;
    return res->interface->update_services(res, NULL, SVS_INSTANCE_STATS, &resp);
}

static int local_handle_path_resolve_service(resolution_path_callback* cb,
        struct service_desc* service, struct net_addr* address) {
    assert(cb);
    service_resolver* res = (service_resolver*) cb->target;
    return res->interface->resolve_service(res, NULL, service, address);
}

static int local_initialize(service_resolver* resolver) {
    assert(resolver);
    struct sv_local_resolver* lres = (struct sv_local_resolver*) resolver;
    int ret = base_resolver_initialize(&lres->resolver.resolver);

    if(ret) {
        return ret;
    }

    task_mutex_init(&lres->peer_mutex);
    task_rwlock_init(&lres->res_lock);

    lres->peer_table = g_hash_table_new_full(service_id_prefix_hash, service_id_prefix_equal, NULL,
            destroy_peer_info);

    //lres->default_peer->interface->initialize(lres->default_peer);
    lres->default_peer->interface->incref(lres->default_peer);

    service_table_initialize(&lres->resolution_table);
    return 0;
}

static void local_start(service_resolver* resolver) {
    assert(resolver);
    if(resolver->resolver.state < INITIALIZED) {
        return;
    }
    struct sv_local_resolver* lres = (struct sv_local_resolver*) resolver;
    /* start the discovery task */
    struct timeval cur;
    cur.tv_sec = lres->disc_interval;
    cur.tv_usec = 0;
    lres->discover_task = add_timer_task(lres, local_discover_task, &cur);
    resolver->resolver.state = ACTIVE;
}

static void local_stop(service_resolver* resolver) {
    assert(resolver);
    if(resolver->resolver.state < ACTIVE) {
        return;
    }
    struct sv_local_resolver* lres = (struct sv_local_resolver*) resolver;

    if(lres->discover_task) {
        remove_timer_task(lres->discover_task);
    }
    resolver->resolver.state = INITIALIZED;
}

static int local_finalize(service_resolver* resolver) {
    assert(resolver);

    struct sv_local_resolver* lres = (struct sv_local_resolver*) resolver;

    lres->default_peer->interface->decref(lres->default_peer);

    task_mutex_destroy(&lres->peer_mutex);
    task_rwlock_destroy(&lres->res_lock);

    if(lres->peer_table) {
        g_hash_table_destroy(lres->peer_table);
        //free(lres->peer_table);
        lres->peer_table = NULL;
    }

    //if(lres->resolution_table) {
    service_table_finalize(&lres->resolution_table);
    //free(lres->resolution_table);
    //lres->resolution_table = NULL;
    //}

    /* cancel the discover task */
    remove_timer_task(lres->discover_task);
    base_resolver_finalize(&lres->resolver.resolver);

    //TODO - finalize the resolution path?
    return 0;
}

static void local_register_callback(service_resolver_callback* cb, int status, void* data) {
    assert(cb);

    struct register_cb_info* cbinfo = (struct register_cb_info*) cb->target;

    if(status == -SV_TIMEOUT) {
        if(cbinfo->type == SV_REGISTER_REQUEST) {
            LOG_ERR("Peer register timed out!");
        } else {
            LOG_ERR("Peer unregister timed out!");
        }
    } else if(status == -SV_ERROR) {
        if(cbinfo->type == SV_REGISTER_REQUEST) {

            LOG_ERR("Peer register error");
        } else {
            LOG_ERR("Peer unregister error");
        }
    }
    g_array_unref(cbinfo->svc_list);
    //g_array_free(cbinfo->svc_list, TRUE);
    free(cbinfo);
}

static int notify_peer_registration(struct sv_local_resolver* lres, service_resolver* peer,
        GArray* svc_list, struct net_addr* address, uint32_t ttl, int type) {
    assert(lres);

    task_mutex_lock(&lres->peer_mutex);

    /* notify the parents if its the first instance */
    GHashTableIter iter;
    g_hash_table_iter_init(&iter, lres->peer_table);

    struct peer_info* pinfo;

    struct register_cb_info* cbinfo;

    //int count = 0;
    while(g_hash_table_iter_next(&iter, NULL, (void**) &pinfo)) {
        if(peer == pinfo->peer) {
            continue;
        }

        if(pinfo->peer->resolver.relation == RELATION_PARENT) {
            g_array_ref(svc_list);
            cbinfo = (struct register_cb_info*) malloc(sizeof(*cbinfo));
            cbinfo->pinfo = pinfo;
            cbinfo->resolver = lres;
            cbinfo->svc_list = svc_list;
            cbinfo->address = address;
            cbinfo->type = type;
            cbinfo->cb.target = cbinfo;
            cbinfo->cb.service_resolver_cb = local_register_callback;

            if(type == SV_REGISTER_REQUEST) {
                pinfo->peer->interface->register_services_async(pinfo->peer,
                        &lres->resolver.resolver, (struct service_desc*) svc_list->data,
                        svc_list->len, address, ttl, &cbinfo->cb);
            } else if(type == SV_UNREGISTER_REQUEST) {
                pinfo->peer->interface->unregister_services_async(pinfo->peer,
                        &lres->resolver.resolver, (struct service_desc*) svc_list->data,
                        svc_list->len, address, &cbinfo->cb);

            }

        }
    }

    task_mutex_unlock(&lres->peer_mutex);
    return 0;
}

/*not responsible for the memory - caller is */
static int local_register_services(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address, uint32_t ttl) {
    assert(resolver);

    if(peer != NULL && address == NULL) {
        //remote registration must include an instance address
        return -EINVAL;
    }

    struct sv_local_resolver* lres = (struct sv_local_resolver*) resolver;
    /* peer can be self! */

    if(address == NULL) {
        /* it's a local registration*/
        printf("Resolver address count: %i\n", resolver_get_address_count(resolver));
        address = resolver_get_address(resolver, 0);
        assert(address);
    }

    LOG_DBG("Locally registering %i services @ %s with ttl %i\n", num_svc, inet_ntoa(address->net_un.un_ip), ttl);

    int count = 0;
    int rcount = 0;
    struct service_reference* sref = NULL;

    /*batch the rpath requests?*/
    GArray* ref_list = NULL;
    GArray* svc_list = g_array_new(FALSE, TRUE, sizeof(*services));

    struct service_resolution sres;
    if(peer) {
        ref_list = g_array_new(FALSE, TRUE, sizeof(sres));
    }

    task_rwlock_wrlock(&lres->res_lock);

    int osize = service_table_size(&lres->resolution_table);
    int i = 0;
    for(; i < num_svc; i++) {
        if(services[i].flags == SVSF_INVALID) {
            continue;
        }
        /*create new reference*/
        if(sref == NULL) {
            sref = (struct service_reference*) malloc(sizeof(*sref));

            if(sref == NULL) {
                LOG_ERR("Could not allocate service reference memory");
                goto err;
            }
        }

        bzero(sref, sizeof(*sref));
        /*default - until updates expand/change */
        sref->capacity = 1;
        sref->registered = get_current_time_ms();
        sref->ttl = ttl;
        /*reference count?? */
        sref->resolver = peer;

        memcpy(&sref->instance.service.sv_srvid, &services[i].service, sizeof(struct service_id));
        sref->instance.service.sv_flags = services[i].flags;
        sref->instance.service.sv_prefix_bits = services[i].prefix;
        memcpy(&sref->instance.address.sin.sin_addr, address, sizeof(*address));

        LOG_DBG("instance address: %s %s\n", inet_ntoa(sref->instance.address.sin.sin_addr), inet_ntoa(address->net_un.un_ip));
        /* priority, proportion, timeouts all default TODO */
        sref->priority = DEFAULT_SERVICE_PRIORITY;
        sref->weight = DEFAULT_SERVICE_WEIGHT;

        count = service_table_add_service_reference(&lres->resolution_table, sref);

        if(count >= 1) {
            rcount++;

            if(ref_list) {
                sres.sv_flags = sref->instance.service.sv_flags;
                sres.sv_prefix_bits = sref->instance.service.sv_prefix_bits;
                memcpy(&sres.srvid, &sref->instance.service.sv_srvid, sizeof(struct service_id));
                memcpy(&sres.address, &sref->instance.address.sin.sin_addr, sizeof(struct net_addr));
                sres.priority = sref->priority;
                sres.weight = sref->weight;
                g_array_append_val(ref_list, sres);
            }

            sref = NULL;
            if(count == 1) {
                /*only notify parent resolvers if this is the first instance*/
                g_array_append_val(svc_list, services[i]);
            }

        }
    }

    if(sref != NULL) {
        free(sref);
    }

    task_rwlock_unlock(&lres->res_lock);

    if(peer) {

        /* remote peer registration - insert into the resolution path
         * this should follow some sort of policy - along with the setting of default priority, weight, and timeouts
         * */
        lres->rpath->interface->add_resolutions(lres->rpath,
                (struct service_resolution*) ref_list->data, ref_list->len);
        g_array_free(ref_list, TRUE);
    }

    if(rcount > 0 && (peer == NULL || peer != resolver)) {
        /* relies on an async callback, so the callback is reponsible for freeing the svc_list*/
        notify_peer_registration(lres, peer, svc_list, address, ttl, SV_REGISTER_REQUEST);
        g_array_unref(svc_list);
    } else {
        g_array_free(svc_list, TRUE);
    }

    if(osize == 0 && rcount > 0) {
        struct timeval cur;
        cur.tv_sec = lres->expire_interval;
        cur.tv_usec = 0;
        lres->expire_task = add_timer_task(lres, local_expire_task, &cur);
    }

    print_service_table(stdout, &lres->resolution_table);
    LOG_DBG("Locally registered %i service instances\n", rcount);
    return rcount;

    err: task_rwlock_unlock(&lres->res_lock);
    return rcount;
}

//zero signifies error, anything else is a xid
static int local_register_services_async(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address, uint32_t ttl,
        service_resolver_callback* callback) {
    return 0;
}

static int local_unregister_services(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address) {
    assert(resolver);

    if(peer != NULL && address == NULL) {
        return -EINVAL;
    }

    struct sv_local_resolver* lres = (struct sv_local_resolver*) resolver;
    /* peer can be self! */

    if(address == NULL) {
        address = resolver_get_address(resolver, 0);
        assert(address);
    }

    LOG_DBG("Locally unregistering %i services @ %s\n", num_svc, inet_ntoa(address->net_un.un_ip));

    int count = 0;
    int rcount = 0;
    struct service_reference* sref = NULL;
    struct service_desc* sdesc = NULL;
    struct service_resolution_stat sres;

    GArray* svc_list = NULL;

    GArray* ref_list = NULL;

    if(peer) {
        ref_list = g_array_new(FALSE, TRUE, sizeof(sres));
    }

    task_rwlock_wrlock(&lres->res_lock);

    int osize = service_table_size(&lres->resolution_table);
    int i = 0;

    /* default policy is to not unregister until last */

    for(; i < num_svc; i++) {
        /* find the service and remove it.. */
        sdesc = &services[i];
        //        sref = service_table_find_service_reference(lres->resolution_table, sdesc->flags,
        //                sdesc->prefix, &sdesc->service, address);

        if((count = service_table_remove_service_reference(&lres->resolution_table, sdesc->flags,
                sdesc->prefix, &sdesc->service, address, NULL)) >= 0) {
            rcount++;

            if(ref_list) {
                bzero(&sres, sizeof(sres));
                init_resolution_from_reference(&sres.res, sref);
                g_array_append_val(ref_list, sres);
            }

            /* default policy is to not unregister until last */
            if(count == 0) {
                if(svc_list == NULL) {
                    svc_list = g_array_new(FALSE, TRUE, sizeof(*sdesc));
                }

                g_array_append_val(svc_list, *sdesc);
            }
        }
    }

    task_rwlock_unlock(&lres->res_lock);

    if(peer) {
        lres->rpath->interface->remove_resolutions(lres->rpath,
                (struct service_resolution_stat*) ref_list->data, ref_list->len);
        g_array_free(ref_list, TRUE);
    }

    if(svc_list) {
        if((peer == NULL || peer != resolver)) {
            /* async unregistration - callback is reponsible for freeing svc_list*/
            notify_peer_registration(lres, peer, svc_list, address, 0, SV_UNREGISTER_REQUEST);
            g_array_unref(svc_list);
        } else {
            g_array_free(svc_list, TRUE);
        }
    }

    if(osize > 0 && rcount == osize) {
        remove_timer_task(lres->expire_task);
    }
    LOG_DBG("Locally unregistered %i service instances\n", rcount);
    return rcount;
}

static int local_unregister_services_async(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address,
        service_resolver_callback* callback) {
    return 0;
}

/* TODO this function would probably be more useful if it actually returned the full resolution set*/
static int local_query_services(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc) {

    assert(resolver);

    struct sv_local_resolver* lres = (struct sv_local_resolver*) resolver;
    LOG_DBG("Locally querying %i services\n", num_svc);

    size_t count = 0;
    int rcount = 0;
    struct service_reference** sref = NULL;
    struct service_desc* sdesc = NULL;

    task_rwlock_rdlock(&lres->res_lock);
    int i = 0;
    for(; i < num_svc; i++) {

        sdesc = &services[i];
        service_table_find_service_references(&lres->resolution_table, sdesc->flags, sdesc->prefix,
                &sdesc->service, &sref, &count);

        if(sref) {
            rcount++;
            int j = 0;
            for(; j < count; j++) {
                sdesc->flags = sref[j]->instance.service.sv_flags;
            }
            /*free the returned memory*/
            free(sref);
        } else {
            sdesc->flags = SVSF_INVALID;
        }
    }

    task_rwlock_unlock(&lres->res_lock);

    return rcount;

}

static int local_query_services_async(service_resolver* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, service_resolver_callback* callback) {
    return 0;
}

static int local_update_services(service_resolver* resolver, service_resolver* peer, uint16_t type,
        stat_response* responses) {
    assert(resolver);
    if(responses == NULL) {
        return -EINVAL;
    }

    LOG_DBG("Locally updating %i service stats(%i)\n", responses->count, type);

    /*incoming stat update */
    struct sv_local_resolver* lres = (struct sv_local_resolver*) resolver;
    //struct service_desc* sdesc = NULL;
    struct service_reference* sref = NULL;

    /* really the only thing we're interested in receiving from a remote service is a service stat */
    int i = 0;
    struct sv_service_stats* stat = NULL;
    struct sv_instance_stats* istat = NULL;

    switch(type) {
        case SVS_SERVICE_STATS:
            /* NOTE: stat response body is a byte blob - network byte order!*/

            /* should this be a write lock - unless the lock is only meant to protect the table?*/
            task_rwlock_rdlock(&lres->res_lock);

            for(; i < responses->count; i++) {
                stat = &((struct sv_service_stats*) responses->data)[i];
                /* TODO -address?? */
                sref = service_table_find_service_reference(&lres->resolution_table,
                        stat->service.flags, stat->service.prefix, &stat->service.service, NULL);

                if(sref) {
                    if(peer) {

                        sref->peer_instance_count = ntohl(stat->instance_count);
                        sref->peer_bytes_dropped = ntohl(stat->bytes_dropped);
                        sref->peer_bytes_resolved = ntohl(stat->bytes_resolved);
                        sref->peer_packets_dropped = ntohl(stat->packets_dropped);
                        sref->peer_packets_resolved = ntohl(stat->packets_resolved);
                        sref->peer_tokens_consumed = ntohl(stat->tokens_consumed);
                    }
                }
            }
            task_rwlock_unlock(&lres->res_lock);
            break;
        case SVS_INSTANCE_STATS:

            /* should this be a write lock - unless the lock is only meant to protect the table?*/
            task_rwlock_rdlock(&lres->res_lock);

            for(; i < responses->count; i++) {
                istat = &((struct sv_instance_stats*) responses->data)[i];
                sref = service_table_find_service_reference(&lres->resolution_table,
                        istat->service.flags, istat->service.prefix, &istat->service.service,
                        &istat->address);

                if(sref) {
                    sref->bytes_resolved += istat->bytes_resolved;
                    sref->packets_resolved += istat->packets_resolved;
                }

            }
            /* notification to resolution/registration handlers TODO */
            task_rwlock_unlock(&lres->res_lock);
            break;
        default:

            return -EINVAL;
    }
    return 0;
}

static int local_get_service_updates(service_resolver* resolver, service_resolver* peer,
        uint16_t type, struct service_desc* services, size_t num_svc, stat_response* responses) {

    /*note that responses should already be allocated - count capped by message sizes*/
    assert(resolver);

    struct sv_local_resolver* lres = (struct sv_local_resolver*) resolver;
    struct service_reference** sref = NULL;
    struct service_resolution_stat* sres = NULL;
    size_t count = 0;
    int stat_index = 0;
    int resolutions = 0;
    /* really the only thing we're interested in receiving from a remote service is a service stat */
    task_rwlock_rdlock(&lres->res_lock);
    int i = 0;
    int j = 0;
    struct sv_instance_stats* istat = NULL;
    struct sv_service_stats* sstat = NULL;
    struct sv_table_stats* tstat = NULL;
    struct sv_router_stats* rstat = NULL;
    switch(type) {
        case SVS_INSTANCE_STATS:

            /* not currently supported - might need cursors if the list is large
             * these should really be batched vs. individual TODO*/
            for(; i < num_svc; i++) {
                /* might need to specify resolutions vs. resolution stats*/
                resolutions = lres->rpath->interface->get_resolutions(lres->rpath, &services[i],
                        (struct service_resolution**) &sres);

                if(sres) {

                    for(; j < resolutions; j++) {
                        istat = &((struct sv_instance_stats*) responses->data)[stat_index];

                        istat->bytes_resolved = sres[j].bytes_resolved;
                        istat->duration_sec = sres[j].duration_sec;
                        istat->duration_nsec = sres[j].duration_nsec;
                        istat->hard_timeout = sres[j].res.hard_timeout;
                        istat->idle_timeout = sres[j].res.idle_timeout;
                        istat->priority = sres[j].res.priority;
                        istat->weight = sres[j].res.weight;
                        istat->packets_resolved = sres[j].packets_resolved;
                        istat->tokens_consumed = sres[j].tokens_consumed;

                        memcpy(&istat->service.service, &sres[j].res.srvid,
                                sizeof(struct service_id));
                        istat->service.flags = sres[j].res.sv_flags;
                        istat->service.prefix = sres[j].res.sv_prefix_bits;

                        stat_index++;
                    }
                }

                free(sres);
            }

            responses->count = stat_index;
            break;
        case SVS_SERVICE_STATS:

            /* NOTE: stat response body is a byte blob - network byte order!*/

            for(i = 0; i < num_svc && stat_index < responses->count; i++) {

                service_table_find_service_references(&lres->resolution_table, services[i].flags,
                        services[i].prefix, &services[i].service, &sref, &count);

                if(sref) {
                    for(j = 0; j < count && stat_index < responses->count; j++) {
                        sstat = &((struct sv_service_stats*) responses->data)[stat_index];

                        /*or add ref capacity?*/
                        sstat->instance_count++;
                        /*take the max or min?*/
                        sstat->duration_sec = (get_current_time_ms() - sref[j]->registered) / 1000;
                        sstat->duration_nsec = (get_current_time_ms() - sref[j]->registered)
                                * 1000000;

                        sstat->service.flags = sref[j]->instance.service.sv_flags;
                        sstat->service.prefix = sref[j]->instance.service.sv_prefix_bits;
                        memcpy(&sstat->service.service, &sref[j]->instance.service.sv_srvid,
                                sizeof(struct service_id));

                        sstat->bytes_resolved += sref[j]->bytes_resolved;
                        sstat->packets_resolved += sref[j]->packets_resolved;
                        sstat->tokens_consumed += sref[j]->tokens_consumed;

                        /* these do not make sense for arbitrary service prefixes...
                         sref->peer_bytes_dropped = ntohl(stat->bytes_dropped);
                         sref->peer_packets_dropped = ntohl(stat->packets_dropped);
                         */
                    }
                    //                    sstat->bytes_resolved = htonl(sstat->bytes_resolved);
                    //                    sstat->packets_resolved = htonl(sstat->packets_resolved);
                    //                    sstat->tokens_consumed = htonl(sstat->tokens_consumed);
                    stat_index++;
                    free(sref);
                }

            }

            break;
        case SVS_TABLE_STATS:
            tstat = (struct sv_table_stats*) responses->data;
            service_table_get_table_stats(&lres->resolution_table, tstat);
            stat_index++;

            break;
        case SVS_ROUTER_STATS:
            rstat = (struct sv_router_stats*) responses->data;
            /* really order/size dependent...*/
            service_table_get_table_stats(&lres->resolution_table, (struct sv_table_stats*) rstat);
            rstat->tables = 1;
            rstat->peers = g_hash_table_size(lres->peer_table);
            stat_index++;

            break;
        default:
            break;

    }

    task_rwlock_unlock(&lres->res_lock);

    return stat_index;
}

static int local_get_service_updates_async(service_resolver* resolver, service_resolver* peer,
        uint16_t type, struct service_desc* desc, size_t num_svc, stat_response* responses,
        service_resolver_callback* callback) {
    return 0;
}

//    static int local_update_services_async(service_resolver* resolver, uint16_t type, struct service_desc*,
//            size_t num_svc, service_resolver_callback* callback);
//
//resolve multiple services?
static int local_resolve_service(service_resolver* resolver, service_resolver* peer,
        struct service_desc* service, struct net_addr* address) {
    assert(resolver);
    if(service == NULL) {
        return -EINVAL;
    }

    LOG_DBG("Locally resolving service SID(%i:%i) %s\n", service->flags, service->prefix, service_id_to_str(&service->service));

    struct sv_local_resolver* lres = (struct sv_local_resolver*) resolver;
    struct service_reference* sref = NULL;

    task_rwlock_rdlock(&lres->res_lock);

    sref = service_table_resolve_service(&lres->resolution_table, service->flags, service->prefix,
            &service->service);

    if(sref) {
        memcpy(address, &sref->instance.address, sizeof(*address));
    } else {
        service->flags = SVSF_INVALID;
        goto error;
    }

    task_rwlock_unlock(&lres->res_lock);

    return 0;
    error: return -1;
}

static int local_resolve_service_async(service_resolver* resolver, service_resolver* peer,
        struct service_desc* service, struct net_addr* address, service_resolver_callback* callback) {
    return 0;
}

static int local_poke_resolver(service_resolver* resolver, service_resolver* peer, uint32_t count) {
    assert(resolver);
    if(peer == NULL) {
        return -EINVAL;
    }
    struct sv_local_resolver* lres = (struct sv_local_resolver*) resolver;
    /* the real "work" is handled in the rpc layer ?
     * here's where we really need the interface as well?
     * */
    //update_last_updated(peer);
    //update_count(peer);
    LOG_DBG("Locally poking resolver by peer %s\n", service_id_to_str(&peer->resolver.resolver_id.sv_srvid));

    task_mutex_lock(&lres->peer_mutex);

    struct peer_info* pinfo = g_hash_table_lookup(lres->peer_table,
            &peer->resolver.resolver_id.sv_srvid);

    if(pinfo == NULL) {
        /* inconsistency detected! */

    } else {
        pinfo->poking = FALSE;
    }

    task_mutex_unlock(&lres->peer_mutex);
    return 0;
}

static int local_poke_resolver_async(service_resolver* resolver, service_resolver* peer,
        uint32_t count, service_resolver_callback* callback) {
    return 0;
}

static int notify_discovery(struct sv_local_resolver* lres, struct peer_info* pinfo, uint16_t flags) {
    /* assumes that last_discovery has been updated already*/

    if(pinfo->last_discovery > pinfo->disc_cooldown) {
        pinfo->disc_cooldown = pinfo->last_discovery + DISCOVERY_COOLDOWN * 1000;
        pinfo->peer->interface->peer_discovered(pinfo->peer, &lres->resolver.resolver, flags);
    }

    return 0;

}

static int propagate_discovery(struct sv_local_resolver* lres, struct peer_info* pinfo,
        uint16_t flags) {
    /* assumes that last_discovery has been updated already
     * only propagate peers to other peers?
     * also assumes that the peer lock is in effect
     * */

    uint16_t rel = pinfo->peer->resolver.relation;
    uint16_t prel = 0;
    if(rel == RELATION_CHILD || rel == RELATION_SELF || rel == RELATION_UNKNOWN || rel
            == RELATION_PARENT) {
        return 0;
    }

    if(pinfo->last_discovery > pinfo->disc_cooldown) {
        pinfo->disc_cooldown = pinfo->last_discovery + DISCOVERY_COOLDOWN * 1000;

        /* there's probably a better way of finding relevant peers */
        GHashTableIter iter;
        g_hash_table_iter_init(&iter, lres->peer_table);

        struct peer_info* rinfo = NULL;

        while(g_hash_table_iter_next(&iter, NULL, (void**) &rinfo)) {
            if(rinfo == NULL) {
                continue;
            }

            prel = rinfo->peer->resolver.relation;

            if(prel == RELATION_PEER) {
                pinfo->peer->interface->peer_discovered(pinfo->peer, &lres->resolver.resolver,
                        flags);
            }
        }
    }

    return 0;

}

static int should_retain_peer(struct sv_local_resolver* lres, service_resolver* peer) {
    /*simple test - if the peer is a parent or child retain it - might want to set a max cap and random sample
     * along with ttl's and such
     */

    uint16_t rel = peer->resolver.relation;
    return rel == RELATION_PARENT || rel == RELATION_CHILD;
}

static void add_peer_resolution(struct sv_local_resolver* lres, service_resolver* peer,
        struct sockaddr_sv* sdesc) {
    struct service_reference* ref = (struct service_reference*) malloc(sizeof(*ref));
    bzero(ref, sizeof(*ref));

    ref = (struct service_reference*) malloc(sizeof(*ref));
    bzero(ref, sizeof(*ref));

    ref->ttl = 0;
    ref->weight = DEFAULT_SERVICE_WEIGHT;
    ref->priority = DEFAULT_SERVICE_PRIORITY;

    if(sdesc) {
        memcpy(&ref->instance.service, sdesc, sizeof(*sdesc));
    }
    memcpy(&ref->instance.address, resolver_get_address(peer, 0), sizeof(struct net_addr));

    service_table_add_service_reference(&lres->resolution_table, ref);

    struct service_resolution res;
    init_resolution_from_reference(&res, ref);

    lres ->rpath->interface->add_resolutions(lres->rpath, &res, 1);
}

static int local_peer_discovered(service_resolver* resolver, service_resolver* peer, uint16_t flags) {
    assert(resolver);

    if(peer == NULL) {
        return -SV_ERR_SYSTEM_ERROR;
    }

    LOG_DBG("Locally discovered peer %s\n", service_id_to_str(&peer->resolver.resolver_id.sv_srvid));

    struct sv_local_resolver* lres = (struct sv_local_resolver*) resolver;
    int retval = 0;
    struct peer_info* pinfo = NULL;
    /* check to see if the peer is known - if not, add him in
     * only reciprocate if no discovery outstanding
     */
    task_mutex_lock(&lres->peer_mutex);

    if(g_hash_table_lookup_extended(lres->peer_table, &peer->resolver.resolver_id.sv_srvid, NULL,
            (void**) &pinfo)) {
        /* the peer has been updated - its still good to respond in case he's forgotten about us
         * might need to "limit" the # of response and propagations per peer - NACK table?
         * */

        /* update the actual peer if the objects differ */
        if(peer != pinfo->peer) {
            //TODO
        }
    } else if(should_retain_peer(lres, peer)) {
        /*decide whether or not to add in the peer based on relationship and other factors */
        pinfo = (struct peer_info*) malloc(sizeof(*pinfo));
        bzero(pinfo, sizeof(*pinfo));
        pinfo->peer = peer;

        if(g_hash_table_size(lres->peer_table) == 0) {
            struct timeval cur;
            cur.tv_sec = lres->echo_interval;
            cur.tv_usec = 0;
            lres->echo_task = add_timer_task(lres, local_echo_task, &cur);
        }

        g_hash_table_insert(lres->peer_table, &peer->resolver.resolver_id.sv_srvid, pinfo);

        pinfo->peer->interface->incref(pinfo->peer);

    } else {
        retval = -SV_ERR_PEER_DECLINED;
        goto decline;
    }

    pinfo->disc_count++;
    pinfo->last_discovery = get_current_time_ms();

    /*inc ref for notification and discovery*/
    pinfo->peer->interface->incref(pinfo->peer);
    task_mutex_unlock(&lres->peer_mutex);

    /*default is to install a resolution rule for the peer's SID, regardless of relation*/
    task_rwlock_wrlock(&lres->res_lock);
    add_peer_resolution(lres, peer, &pinfo->peer->resolver.resolver_id);

    /*if the peer is a parent, install the default resolutions*/
    if(pinfo->peer->resolver.relation == RELATION_PARENT) {
        add_peer_resolution(lres, peer, NULL);
    }
    task_rwlock_unlock(&lres->res_lock);

    if(PROPAGATE_TTL(flags) > 0) {
        propagate_discovery(lres, pinfo, DEC_PROPAGATE_TTL(flags, 1));
    }

    /*peer reference inc'd*/
    if(flags & DISCOVER_NOTIFY) {
        /*respond back to peer with discovery*/
        notify_discovery(lres, pinfo, flags & ~DISCOVER_NOTIFY);
    }

    pinfo->peer->interface->decref(pinfo->peer);
    return retval;

    decline: task_mutex_unlock(&lres->peer_mutex);

    return retval;
}

static int local_peer_disappeared(service_resolver* resolver, service_resolver* peer,
        uint16_t flags) {
    assert(resolver);
    if(peer == NULL) {
        return -SV_ERR_PEER_UNKNOWN;
    }

    LOG_DBG("Locally disappeared peer %s\n", service_id_to_str(&peer->resolver.resolver_id.sv_srvid));

    struct sv_local_resolver* lres = (struct sv_local_resolver*) resolver;
    int retval = 0;
    /* check to see if the peer is known - if not, add him in
     * only reciprocate if no discovery outstanding
     */
    task_mutex_lock(&lres->peer_mutex);

    if(g_hash_table_lookup_extended(lres->peer_table, &peer->resolver.resolver_id.sv_srvid, NULL,
            NULL)) {
        /* the peer has been updated - its still good to respond in case he's forgotten about us
         * might need to "limit" the # of response and propagations per peer - NACK table?
         * */

        /*for the purge use*/
        peer->interface->incref(peer);

        g_hash_table_remove(lres->peer_table, &peer->resolver.resolver_id.sv_srvid);
    } else {
        retval = -SV_ERR_PEER_UNKNOWN;
        goto error;
    }
    /*of the hash table reference*/
    task_mutex_unlock(&lres->peer_mutex);

    notify_peer_status_callbacks((service_resolver*) lres, peer, DISAPPEARED);
    /*remove the default resolutions*/
    task_rwlock_wrlock(&lres->res_lock);
    purge_peer_resolution(lres, peer, NULL);

    if(peer->resolver.relation == RELATION_PARENT) {
        purge_peer_resolution(lres, peer, &peer->resolver.resolver_id);
    }
    task_rwlock_unlock(&lres->res_lock);

    if(PROPAGATE_TTL(flags) > 0) {
        //propagate_disappearance(lres, peer, DEC_PROPAGATE_TTL(flags, 1));
    }

    peer->interface->decref(peer);

    out: return retval;

    error: task_mutex_unlock(&lres->peer_mutex);
    goto out;

}
