/*
 * resolution_path.c
 *
 *  Created on: Feb 24, 2011
 *      Author: daveds
 */

#include <assert.h>
#include <glib.h>

#include "debug.h"
#include "resolution_path.h"
#include "message_channel.h"
#include "task.h"

extern void create_netlink_message_channel(int protocol, int buffer_len, int reliable,
        message_channel_callback* callback, message_channel* channel);

extern void create_unix_message_channel(const char* lpath, const char* rpath, int buffer_len,
        message_channel_callback* callback, message_channel* channel);

struct sv_resolution_path {

    //resolution_path_callback res_callback;
    service_resolver resolver;

    atomic_t request_xid;

    GHashTable* message_table;
    task_mutex message_mutex;
    task_cond message_cond;

    message_channel_callback callback;
    message_channel channel;
};

static int initialize(void* path);
static void stop(void*path);
static void start(void*path);

static int finalize(void* path);
static const service_resolver* get_resolver(void* target);
static void set_resolver(void* target, service_resolver* resolver);

static int configure_interface(void* path, const char *ifname, const struct net_addr *ipaddr,
        unsigned short flags);
static int get_service_stats(void* path, struct service_stat* stats);
static void set_transit(void* path, int transit);
static int get_resolutions(void* path, struct service_desc* service,
        struct service_resolution**resolutions);
static int get_resolutions_async(void* path, struct service_desc* service,
        resolution_path_callback callback);

static int add_resolutions(void* path, struct service_resolution* resolutions, size_t res_count);
static int add_resolutions_async(void* path, struct service_resolution* resolutions,
        size_t res_count, resolution_path_callback callback);

static int remove_resolutions(void* path, struct service_resolution_stat* service, size_t res_count);
static int remove_resolutions_async(void* path, struct service_resolution_stat* service,
        resolution_path_callback callback);

static int modify_resolutions(void* path, struct service_resolution* resolutions, size_t res_count);
static int modify_resolutions_async(void* path, struct service_resolution* resolutions,
        size_t res_count, resolution_path_callback callback);

struct sv_resolution_path_interface sv_res_path_interface = {
        .initialize = initialize,
        .start = start,
        .stop = stop,
        .finalize = finalize,
        .set_resolver = set_resolver,
        .get_resolver = get_resolver,
        .configure_interface = configure_interface,
        .get_service_stats = get_service_stats,
        .set_transit = set_transit,
        .get_resolutions = get_resolutions,
        .get_resolutions_async = get_resolutions_async,
        .add_resolutions = add_resolutions,
        .add_resolutions_async = add_resolutions_async,
        .remove_resolutions = remove_resolutions,
        .remove_resolutions_async = remove_resolutions_async,
        .modify_resolutions = modify_resolutions,
        .modify_resolutions_async = modify_resolutions_async

//to-kernel messages
        //CTRLMSG_TYPE_IFACE_CONF = 100,
        //CTRLMSG_TYPE_SET_SERVICE = 101,
        };

struct get_resolution_barrier {
    struct message_barrier barrier;
    int count;

    struct service_resolution* resolutions;
};

struct stat_resolution_barrier {
    struct message_barrier barrier;
    struct service_stat* stats;
};

static int resolution_path_message_channel_cb(void* target, const void* message, size_t length);
static void init_message_barrier(struct message_barrier* barrier, struct sv_resolution_path* spath,
        uint16_t type, barrier_handler sh, barrier_handler fh);
static void resolution_path_handle_success_get(struct message_barrier* barrier, const void* msg,
        size_t len);

static void handle_register_message(struct sv_resolution_path* spath,
        struct ctrlmsg_register* message, size_t length);
static void handle_unregister_message(struct sv_resolution_path* spath,
        struct ctrlmsg_register* message, size_t length);
static void handle_resolve_message(struct sv_resolution_path* spath,
        struct ctrlmsg_resolve* message, size_t length);
static void handle_resolution_removed(struct sv_resolution_path* spath,
        struct ctrlmsg_resolution* message, size_t length);

void create_resolution_path(resolution_path* respath) {
    struct sv_resolution_path* spath = (struct sv_resolution_path*) malloc(sizeof(*spath));
    bzero(spath, sizeof(*spath));
    //spath->resolver = *resolver;

    spath->callback.target = spath;
    spath->callback.recv_message = resolution_path_message_channel_cb;

    /* start with the kernel version */
    create_netlink_message_channel(NETLINK_SERVAL, 0, 0, &spath->callback, &spath->channel);
    respath->interface = &sv_res_path_interface;
    respath->target = spath;
}

static int initialize(void* path) {
    assert(path);
    struct sv_resolution_path* spath = (struct sv_resolution_path*) path;

    spath->message_table = g_hash_table_new_full(g_int_hash, g_int_equal, destroy_int_key, NULL);

    if(spath->channel.interface->initialize(spath->channel.target)) {
        spath->channel.interface->finalize(spath->channel.target);
        free(spath->channel.target);
        spath->channel.target = NULL;
        spath->channel.interface = NULL;
        /*try the unix version */
        create_unix_message_channel(SERVAL_SCAFD_CTRL_PATH, SERVAL_STACK_CTRL_PATH, 0,
                &spath->callback, &spath->channel);

        if(spath->channel.interface->initialize(spath->channel.target)) {
            /* TODO error! */
        }
    }

    task_mutex_init(&spath->message_mutex);
    task_cond_init(&spath->message_cond);
    return 0;

}

static void start(void*path) {
    assert(path);
    struct sv_resolution_path* spath = (struct sv_resolution_path*) path;
    spath->channel.interface->start(spath->channel.target);
}
static void stop(void*path) {
    assert(path);
    struct sv_resolution_path* spath = (struct sv_resolution_path*) path;
    spath->channel.interface->stop(spath->channel.target);
}

static int finalize(void* path) {
    assert(path);
    struct sv_resolution_path* spath = (struct sv_resolution_path*) path;

    if(spath->channel.target) {
        spath->channel.interface->finalize(spath->channel.target);
        spath->channel.target = NULL;
    }

    g_hash_table_destroy(spath->message_table);
    //free(spath->message_table);
    task_mutex_destroy(&spath->message_mutex);
    task_cond_destroy(&spath->message_cond);

    return 0;
}

static void set_resolver(void* target, service_resolver* resolver) {
    assert(target);
    struct sv_resolution_path* spath = (struct sv_resolution_path*) target;
    spath->resolver = *resolver;
}

static const service_resolver* get_resolver(void* target) {
    assert(target);
    struct sv_resolution_path* spath = (struct sv_resolution_path*) target;
    return &spath->resolver;
}

static inline void init_message_barrier(struct message_barrier* barrier,
        struct sv_resolution_path* spath, uint16_t type, barrier_handler sh, barrier_handler fh) {
    barrier->private = spath;
    barrier->type = type;
    barrier->barrier_cond = spath->message_cond;
    barrier->barrier_mutex = spath->message_mutex;
    barrier->success_handler = sh;
    barrier->failure_handler = fh;

}

static void resolution_path_handle_success_get(struct message_barrier* barrier, const void* msg,
        size_t len) {
    struct get_resolution_barrier* gbarrier = (struct get_resolution_barrier*) barrier;

    struct ctrlmsg* cmsg = (struct ctrlmsg*) msg;

    if(cmsg->len == CTRLMSG_GET_SERVICE_SIZE && ((struct ctrlmsg_get_service*) cmsg)->sv_prefix_bits == SVSF_INVALID) {
        //TODO - invalid service ID
        return;
    }

    struct ctrlmsg_resolution* rmessage = (struct ctrlmsg_resolution*) msg;

    int rescount = CTRL_NUM_SERVICES(rmessage, len);

    if(rescount == 0) {
        return;
    }
    /* not a great mem management tech here */

    if(gbarrier->count == 0) {
        gbarrier->resolutions = (struct service_resolution*) malloc(
                rescount * sizeof(struct service_resolution));
    } else {
        gbarrier->resolutions = (struct service_resolution*) realloc(gbarrier,
                (gbarrier->count + rescount) * sizeof(struct service_resolution));
    }
    int i = 0;
    for (; i < rescount; i++) {
        memcpy(&gbarrier->resolutions[gbarrier->count++], &rmessage->resolution[i],
                sizeof(struct service_resolution));
    }

}

static void resolution_path_handle_success_stat(struct message_barrier* barrier, const void* msg,
        size_t len) {
    struct stat_resolution_barrier* sbarrier = (struct stat_resolution_barrier*) barrier;

    struct ctrlmsg_stats* smessage = (struct ctrlmsg_stats*) msg;

    /* not a great mem management tech here */

    memcpy(sbarrier->stats, &smessage->stats, sizeof(smessage->stats));
}

static int get_service_stats(void* path, struct service_stat* stats) {
    assert(path);
    struct sv_resolution_path* spath = (struct sv_resolution_path*) path;

    /* no copying, no resend */
    struct ctrlmsg_stats cm;

    memset(&cm, 0, sizeof(cm));
    cm.cmh.type = CTRLMSG_TYPE_SERVICE_STATS;
    cm.cmh.len = sizeof(cm);
    cm.xid = atomic_add_return(1, &spath->request_xid);

    struct stat_resolution_barrier barrier;
    bzero(&barrier, sizeof(barrier));
    barrier.stats = stats;

    init_message_barrier(&barrier.barrier, spath, CTRLMSG_TYPE_SERVICE_STATS,
            resolution_path_handle_success_stat, message_barrier_handle_failure_default);

    task_mutex_lock(&spath->message_mutex);
    uint32_t* xid = (uint32_t*) malloc(sizeof(*xid));
    *xid = cm.xid;

    g_hash_table_insert(spath->message_table, xid, &barrier);
    task_mutex_unlock(&spath->message_mutex);

    spath->channel.interface->send_message(spath->channel.target, &cm, sizeof(cm));

    wait_for_message_barrier(&barrier.barrier);
    return 0;

}

static int configure_interface(void* path, const char *ifname, const struct net_addr *ipaddr,
        unsigned short flags) {
    assert(path);
    struct sv_resolution_path* spath = (struct sv_resolution_path*) path;

    struct ctrlmsg_iface_conf cm;

    if(ifname == NULL) {
        /*should be EINVAL*/
        return -1;
    }

    memset(&cm, 0, sizeof(cm));
    cm.cmh.type = CTRLMSG_TYPE_IFACE_CONF;
    cm.cmh.len = sizeof(cm);
    strncpy(cm.ifname, ifname, IFNAMSIZ - 1);
    if(ipaddr)
        memcpy(&cm.ipaddr, ipaddr, sizeof(*ipaddr));
    cm.flags = flags;

    /*async message - send it!*/
    int retval = spath->channel.interface->send_message(spath->channel.target, &cm, sizeof(cm));

    return retval;
}

static int get_resolutions(void* path, struct service_desc* service,
        struct service_resolution**resolutions) {
    assert(path);
    struct sv_resolution_path* spath = (struct sv_resolution_path*) path;

    /* no copying, no resend */
    struct ctrlmsg_get_service cm;

    memset(&cm, 0, sizeof(cm));
    cm.cmh.type = CTRLMSG_TYPE_GET_SERVICE;
    cm.cmh.len = sizeof(cm);
    cm.sv_flags = service->flags;
    cm.sv_prefix_bits = service->prefix;
    cm.xid = atomic_add_return(1, &spath->request_xid);

    memcpy(&cm.srvid, &service->service, sizeof(struct service_id));

    struct get_resolution_barrier barrier;
    bzero(&barrier, sizeof(barrier));

    init_message_barrier(&barrier.barrier, spath, CTRLMSG_TYPE_GET_SERVICE,
            resolution_path_handle_success_get, message_barrier_handle_failure_default);

    task_mutex_lock(&spath->message_mutex);
    uint32_t* xid = (uint32_t*) malloc(sizeof(*xid));
    *xid = cm.xid;

    g_hash_table_insert(spath->message_table, xid, &barrier);
    task_mutex_unlock(&spath->message_mutex);

    spath->channel.interface->send_message(spath->channel.target, &cm, sizeof(cm));

    wait_for_message_barrier(&barrier.barrier);

    *resolutions = barrier.resolutions;
    return barrier.count;

}
static int get_resolutions_async(void* path, struct service_desc* service,
        resolution_path_callback callback) {
    return 0;
}

static int add_resolutions(void* path, struct service_resolution* resolutions, size_t res_count) {
    assert(path);
    if(resolutions == NULL) {
        return EINVAL;
    }
    if(res_count == 0) {
        return 0;
    }
    struct sv_resolution_path* spath = (struct sv_resolution_path*) path;

    LOG_DBG("Adding %i stack resolution rules\n", res_count);
    /* no copying, no resend */
    int size = sizeof(struct ctrlmsg_resolution) + res_count * sizeof(*resolutions);
    //struct ctrlmsg_resolution* cm = (struct ctrlmsg_resolution*) malloc(size);
    struct ctrlmsg_resolution cm;

    bzero(&cm, sizeof(cm));
    cm.cmh.type = CTRLMSG_TYPE_ADD_SERVICE;
    cm.cmh.len = size;
    //cm.xid = atomic_add_return(1, &spath->request_xid);

    /*would be better with scatter gather? */
    //    int i = 0;
    //    for(; i < res_count; i++) {
    //        memcpy(&cm->resolution[i], &resolutions[i], sizeof(*resolutions));
    //    }

    struct iovec iov[2] = { { (void*) &cm, sizeof(cm) }, { (void*) resolutions, res_count
            * sizeof(*resolutions) } };

    int retval = spath->channel.interface->send_message_iov(spath->channel.target, iov, 2, size);

    /* response handled as event*/
    return retval;
}

static int _add_resolutions(void* path, struct service_resolution* resolutions, size_t res_count) {
    assert(path);
    if(resolutions == NULL || res_count <= 0) {
        return -1;
    }

    struct sv_resolution_path* spath = (struct sv_resolution_path*) path;

    /*adds a single service at a time..and is async..yuck*/
    struct ctrlmsg_service cm;

    memset(&cm, 0, sizeof(cm));
    cm.cmh.type = CTRLMSG_TYPE_ADD_SERVICE;
    cm.cmh.len = sizeof(cm);
    int i = 0;

    for (; i < res_count; i++) {

        cm.prefix_bits = resolutions[i].sv_prefix_bits > 255 ? 255 : resolutions[i].sv_prefix_bits;
        memcpy(&cm.srvid, &resolutions[i].srvid, sizeof(struct service_id));
        memcpy(&cm.ipaddr, &resolutions[i].address.net_un.un_ip, sizeof(struct in_addr));

        spath->channel.interface->send_message(spath->channel.target, &cm, sizeof(cm));
    }

    return 0;
}

static int _remove_resolutions(void* path, struct service_resolution* resolutions, size_t res_count) {
    assert(path);
    if(resolutions == NULL || res_count <= 0) {
        return -1;
    }

    struct sv_resolution_path* spath = (struct sv_resolution_path*) path;

    struct ctrlmsg_service cm;
    cm.cmh.type = CTRLMSG_TYPE_DEL_SERVICE;
    cm.cmh.len = sizeof(cm);

    memset(&cm, 0, sizeof(cm));

    int i = 0;

    for (; i < res_count; i++) {

        cm.prefix_bits = resolutions[i].sv_prefix_bits > 255 ? 255 : resolutions[i].sv_prefix_bits;
        memcpy(&cm.srvid, &resolutions[i].srvid, sizeof(struct service_id));
        memcpy(&cm.ipaddr, &resolutions[i].address.net_un.un_ip, sizeof(struct in_addr));

        /* send message must send or fail then return. it cannot return
         * incomplete.
         */
        spath->channel.interface->send_message(spath->channel.target, &cm, sizeof(cm));
    }

    return 0;
}

static int add_resolutions_async(void* path, struct service_resolution* resolutions,
        size_t res_count, resolution_path_callback callback) {
    return 0;
}

static int remove_resolutions(void* path, struct service_resolution_stat* resolutions, size_t res_count) {

    assert(path);
    if(resolutions == NULL) {
        return EINVAL;
    }
    if(res_count == 0) {
        return 0;
    }
    struct sv_resolution_path* spath = (struct sv_resolution_path*) path;

    LOG_DBG("Removing %i stack resolution rules\n", res_count);

    int size = sizeof(struct ctrlmsg_resolution) + res_count * sizeof(*resolutions);
    //struct ctrlmsg_resolution* cm = (struct ctrlmsg_resolution*) malloc(size);
    struct ctrlmsg_resolution cm;

    bzero(&cm, sizeof(cm));
    cm.cmh.type = CTRLMSG_TYPE_DEL_SERVICE;
    cm.cmh.len = size;
    //cm.xid = atomic_add_return(1, &spath->request_xid);

    struct iovec iov[2] = { { (void*) &cm, sizeof(cm) }, { (void*) resolutions, res_count
            * sizeof(*resolutions) } };

    int retval = spath->channel.interface->send_message_iov(spath->channel.target, iov, 2, size);
    /* response handled as remove event*/
    return retval;

}
static int remove_resolutions_async(void* path, struct service_resolution_stat* service,
        resolution_path_callback callback) {
    return 0;
}

static void set_transit(void* path, int transit) {
    assert(path);
    struct sv_resolution_path* spath = (struct sv_resolution_path*) path;
    LOG_DBG("Setting resolution path to transit mode: %i\n", transit);

    struct ctrlmsg_set_transit cm;
    bzero(&cm, sizeof(cm));
    cm.cmh.type = CTRLMSG_TYPE_SET_TRANSIT;
    cm.cmh.len = sizeof(cm);

    //    cm.xid = atomic_add_return(1, &spath->request_xid);
    //    struct message_barrier barrier;
    //    bzero(&barrier, sizeof(barrier));
    //
    //    init_message_barrier(&barrier, spath, CTRLMSG_TYPE_SET_TRANSIT,
    //            message_barrier_handle_success_default, message_barrier_handle_failure_default);
    //
    //    task_mutex_lock(&spath->message_mutex);
    //
    //    uint32_t* xid = (uint32_t*) malloc(sizeof(*xid));
    //    *xid = cm.xid;
    //
    //    g_hash_table_insert(spath->message_table, xid, &barrier);
    //    task_mutex_unlock(&spath->message_mutex);

    int retval = spath->channel.interface->send_message(spath->channel.target, &cm, sizeof(cm));

    // wait_for_message_barrier(&barrier);

}

static int modify_resolutions(void* path, struct service_resolution* resolutions, size_t res_count) {
    assert(path);
    if(resolutions == NULL) {
        return EINVAL;
    }
    if(res_count == 0) {
        return 0;
    }
    struct sv_resolution_path* spath = (struct sv_resolution_path*) path;

    LOG_DBG("Modifying %i stack resolution rules\n", res_count);
    /* no copying, no resend */
    int size = sizeof(struct ctrlmsg_resolution) + res_count * sizeof(*resolutions);
    //struct ctrlmsg_resolution* cm = (struct ctrlmsg_resolution*) malloc(size);
    struct ctrlmsg_resolution cm;
    bzero(&cm, sizeof(cm));
    cm.cmh.type = CTRLMSG_TYPE_MOD_SERVICE;
    cm.cmh.len = size;

    struct iovec iov[2] = { { (void*) &cm, sizeof(cm) }, { (void*) resolutions, res_count
            * sizeof(*resolutions) } };

    int retval = spath->channel.interface->send_message_iov(spath->channel.target, iov, 2, size);

    return retval;

}
static int modify_resolutions_async(void* path, struct service_resolution* resolutions,
        size_t res_count, resolution_path_callback callback) {
    return 0;
}

static void handle_register_message(struct sv_resolution_path* spath,
        struct ctrlmsg_register* message, size_t length) {
    LOG_DBG("Handling stack-local register: SID(%i:%i) %s\n", message->sv_flags, message->sv_prefix_bits, service_id_to_str(&message->srvid));
    struct service_desc sdesc;
    sdesc.flags = message->sv_flags;
    sdesc.prefix = message->sv_prefix_bits;
    memcpy(&sdesc.service, &message->srvid, sizeof(struct service_id));
    spath->resolver.interface->register_services(spath->resolver.target, NULL, &sdesc, 1, NULL, 0);

}

static void handle_unregister_message(struct sv_resolution_path* spath,
        struct ctrlmsg_register* message, size_t length) {
    LOG_DBG("Handling stack-local unregister: SID(%i:%i) %s\n", message->sv_flags, message->sv_prefix_bits, service_id_to_str(&message->srvid));
    struct service_desc sdesc;
    sdesc.flags = message->sv_flags;
    sdesc.prefix = message->sv_prefix_bits;
    memcpy(&sdesc.service, &message->srvid, sizeof(struct service_id));
    spath->resolver.interface->unregister_services(spath->resolver.target, NULL, &sdesc, 1, NULL);
}

static void handle_resolve_message(struct sv_resolution_path* spath,
        struct ctrlmsg_resolve* message, size_t length) {
    /*note that the resolve message could/should include src SID and IP and TODO */
    LOG_DBG("Handling resolve: src SID(%i:%i) %s dst SID(%i:%i) %s\n", message->src_flags, message->src_prefix_bits, service_id_to_str(&message->src_srvid),
            message->dst_flags, message->dst_prefix_bits, service_id_to_str(&message->dst_srvid));



}

static void handle_resolution_removed(struct sv_resolution_path* spath,
        struct ctrlmsg_resolution* message, size_t length) {
    /*TODO - big assumption that the resolutions here include stats */
    int rcount = CTRL_NUM_STAT_SERVICES(message, length);
    LOG_DBG("Handling resolution removed: %i\n", rcount);

    stat_response resp;
    resp.count = rcount;
    resp.type = SVS_INSTANCE_STATS;
    resp.data = (uint8_t*) &message->resolution;

    spath->resolver.interface->update_services(spath->resolver.target, NULL, SVS_INSTANCE_STATS,
            &resp);

}

static void handle_resolution_added(struct sv_resolution_path* spath,
        struct ctrlmsg_resolution* message, size_t length) {
    /*DO NOTHING for now - may need to verify actual resolutions added TODO*/
    LOG_DBG("Handling resolution added: %i\n", length);
}

static void handle_resolution_modified(struct sv_resolution_path* spath,
        struct ctrlmsg_resolution* message, size_t length) {
    /*DO NOTHING for now TODO*/
    LOG_DBG("Handling resolution modified: %i\n", length);
}

static int resolution_path_message_channel_cb(void* target, const void* message, size_t length) {
    assert(target);

    struct ctrlmsg* cmsg = (struct ctrlmsg*) message;
    struct ctrlmsg_resolution* amsg;
    struct sv_resolution_path* spath = (struct sv_resolution_path*) target;
    struct message_barrier* barrier = NULL;

    switch (cmsg->type) {
    case CTRLMSG_TYPE_REGISTER:
        handle_register_message(spath, (struct ctrlmsg_register*) message, length);
        break;
    case CTRLMSG_TYPE_UNREGISTER:
        handle_unregister_message(spath, (struct ctrlmsg_register*) message, length);
        break;
    case CTRLMSG_TYPE_RESOLVE:
        handle_resolve_message(spath, (struct ctrlmsg_resolve*) message, length);
        break;
    case CTRLMSG_TYPE_ADD_SERVICE:
        handle_resolution_added(spath, (struct ctrlmsg_resolution*) message, length);
        break;
    case CTRLMSG_TYPE_DEL_SERVICE:
        handle_resolution_removed(spath, (struct ctrlmsg_resolution*) message, length);
        break;
    case CTRLMSG_TYPE_MOD_SERVICE:
        handle_resolution_modified(spath, (struct ctrlmsg_resolution*) message, length);
        break;
    case CTRLMSG_TYPE_GET_SERVICE:
    case CTRLMSG_TYPE_SERVICE_STATS:
        //case CTRLMSG_TYPE_SET_TRANSIT:
        task_mutex_lock(&spath->message_mutex);

        /* TODO although it's a bit dangerous to cast solely to the resolution message,
         * the xid is in the same field position
         */
        amsg = (struct ctrlmsg_resolution*) message;
        barrier = (struct message_barrier*) g_hash_table_lookup(spath->message_table, &amsg->xid);

        if(barrier == NULL) {
            task_mutex_unlock(&spath->message_mutex);
            LOG_ERR("Resolution response received for unknown request: %u", amsg->xid);
        } else {
            g_hash_table_remove(spath->message_table, &amsg->xid);
            task_mutex_unlock(&spath->message_mutex);
            message_barrier_default_cb(barrier, cmsg->type, message, length);
        }
        break;
    }

    return 0;
}
