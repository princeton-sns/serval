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

extern message_channel *create_netlink_message_channel(int protocol,
						       int buffer_len,
						       int reliable,
						       message_channel_callback
						       * callback);

extern message_channel *create_unix_message_channel(const char *lpath,
						    const char *rpath,
						    int buffer_len,
						    message_channel_callback
						    * callback);

static int initialize(resolution_path * path);
static void stop(resolution_path * path);
static void start(resolution_path * path);

static int finalize(resolution_path * path);
static const resolution_path_callback *get_path_callback(resolution_path *
							 path);
static void set_path_callback(resolution_path * path,
			      resolution_path_callback * cb);

static int configure_interface(resolution_path * path, const char *ifname,
			       const struct net_addr *ipaddr,
			       unsigned short flags);
static int get_service_stats(resolution_path * path,
			     struct service_stat *stats);
static void set_capabilities(resolution_path * path, int capabilities);
static int get_resolutions(resolution_path * path,
			   struct service_desc *service,
			   struct service_info **resolutions);
static int get_resolutions_async(resolution_path * path,
				 struct service_desc *service,
				 resolution_path_callback callback);

static int add_resolutions(resolution_path * path,
			   struct service_info *resolutions, size_t res_count);
static int add_resolutions_async(resolution_path * path,
				 struct service_info *resolutions,
				 size_t res_count,
				 resolution_path_callback callback);

static int remove_resolutions(resolution_path * path,
			      struct service_info_stat *service,
			      size_t res_count);
static int remove_resolutions_async(resolution_path * path,
				    struct service_info_stat *service,
				    resolution_path_callback callback);

static int modify_resolutions(resolution_path * path,
			      struct service_info *resolutions,
			      size_t res_count);
static int modify_resolutions_async(resolution_path * path,
				    struct service_info *resolutions,
				    size_t res_count,
				    resolution_path_callback callback);

/*resolution path prototype*/
struct sv_resolution_path_interface sv_res_path_interface = {
    .initialize = initialize,
    .start = start,
    .stop = stop,
    .finalize = finalize,
    .set_path_callback = set_path_callback,
    .get_path_callback = get_path_callback,
    .configure_interface = configure_interface,
    .get_service_stats = get_service_stats,
    .set_capabilities = set_capabilities,
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
    struct service_info *resolutions;
};

struct stat_resolution_barrier {
    struct message_barrier barrier;
    struct service_stat *stats;
};

static int resolution_path_message_channel_cb(message_channel_callback *
					      cb, const void *message,
					      size_t length);

static void resolution_path_handle_success_get(struct message_barrier
					       *barrier, const void *msg,
					       size_t len);

static void handle_register_message(resolution_path * spath,
				    struct ctrlmsg_register *message,
				    size_t length);
static void handle_unregister_message(resolution_path * spath,
				      struct ctrlmsg_register *message,
				      size_t length);
static void handle_resolve_message(resolution_path * spath,
				   struct ctrlmsg_resolve *message,
				   size_t length);
static void handle_resolution_removed(resolution_path * spath, struct ctrlmsg_service_stats
				      *message, size_t length);

void init_resolution_path(resolution_path * spath)
{
    bzero(spath, sizeof(*spath));

    spath->path.callback.target = spath;
    spath->path.callback.recv_message = resolution_path_message_channel_cb;

    /* start with the kernel stack netlink interface */
    spath->path.channel =
	create_netlink_message_channel(NETLINK_SERVAL, 0, 0,
				       &spath->path.callback);
    spath->interface = &sv_res_path_interface;
}

/* really more of an init/constructor function - malloc must occur externally*/
resolution_path *create_resolution_path()
{
    resolution_path *spath =
	(resolution_path *) malloc(sizeof(resolution_path));

    init_resolution_path(spath);
    return spath;
}

static int initialize(resolution_path * spath)
{
    assert(spath);

    if (!is_created(spath->path.state)) {
	return -1;
    }
    spath->path.message_table =
	g_hash_table_new_full(g_int_hash, g_int_equal, destroy_int_key, NULL);

    if (spath->path.channel->interface->initialize(spath->path.channel)) {
	spath->path.channel->interface->finalize(spath->path.channel);
	free(spath->path.channel);

	/*try the unix version */
	if (spath->path.stack_id > 0) {
	    char stack_buffer[128];
	    sprintf(stack_buffer, "/tmp/serval-stack-ctrl-%i.sock",
		    spath->path.stack_id);
	    char local_buffer[128];
	    sprintf(local_buffer, "/tmp/serval-libstack-ctrl-%i.sock",
		    spath->path.stack_id);
	    spath->path.channel =
		create_unix_message_channel(local_buffer, stack_buffer, 0,
					    &spath->path.callback);
	} else {
	    spath->path.channel =
		create_unix_message_channel(SERVAL_SERVD_CTRL_PATH,
					    SERVAL_STACK_CTRL_PATH, 0,
					    &spath->path.callback);
	}

	if (spath->path.channel->interface->initialize(spath->path.channel)) {
	    /* TODO error! */
	}
    }

    task_mutex_init(&spath->path.message_mutex);
    task_cond_init(&spath->path.message_cond);
    spath->path.state = COMP_INITIALIZED;
    return 0;
}

static void start(resolution_path * spath)
{
    assert(spath);
    if (!is_initialized(spath->path.state)) {
	return;
    }
    spath->path.channel->interface->start(spath->path.channel);
    spath->path.state = COMP_STARTED;
}

static void stop(resolution_path * spath)
{
    assert(spath);
    if (!is_started(spath->path.state)) {
	return;
    }
    spath->path.channel->interface->stop(spath->path.channel);
    spath->path.state = COMP_INITIALIZED;
}

static int finalize(resolution_path * spath)
{
    assert(spath);

    if (spath->path.channel) {
	spath->path.channel->interface->finalize(spath->path.channel);
	/*owner of the channel - free it */
	free(spath->path.channel);
	spath->path.channel = NULL;
    }

    g_hash_table_destroy(spath->path.message_table);

    task_mutex_destroy(&spath->path.message_mutex);
    task_cond_destroy(&spath->path.message_cond);
    spath->path.state = COMP_CREATED;
    return 0;
}

static void set_path_callback(resolution_path * spath,
			      resolution_path_callback * cb)
{
    assert(spath);
    spath->path.path_callback = *cb;
}

static const resolution_path_callback *get_path_callback(resolution_path *
							 spath)
{
    assert(spath);
    return &spath->path.path_callback;
}

static void resolution_path_handle_success_get(struct message_barrier
					       *barrier, const void *msg,
					       size_t len)
{
    assert(barrier);

    if (msg == NULL || len == 0) {
	barrier->status = EINVAL;
	return;
    }

    struct get_resolution_barrier *gbarrier =
	(struct get_resolution_barrier *) barrier;

    struct ctrlmsg *cmsg = (struct ctrlmsg *) msg;

    if (cmsg->len == CTRLMSG_GET_SERVICE_SIZE
	&& ((struct ctrlmsg_service *) cmsg)->service[0].srvid_prefix_bits ==
	SVSF_INVALID) {
	//TODO - invalid service ID
	barrier->status = EINVAL;
	return;
    }

    struct ctrlmsg_service *rmessage = (struct ctrlmsg_service *) msg;

    int rescount = CTRLMSG_SERVICE_NUM(rmessage);

    if (rescount == 0) {
	return;
    }
    /* not a great mem management tech here */

    if (gbarrier->count == 0) {
	gbarrier->resolutions = (struct service_info *) malloc(rescount
							       *
							       sizeof
							       (struct
								service_info));
    } else {
	gbarrier->resolutions =
	    (struct service_info *) realloc(gbarrier,
					    (gbarrier->count +
					     rescount) *
					    sizeof(struct service_info));
    }
    int i = 0;
    for (; i < rescount; i++) {
	memcpy(&gbarrier->resolutions[gbarrier->count++],
	       &rmessage->service[i], sizeof(struct service_info));
    }

}

static void resolution_path_handle_success_stat(struct message_barrier
						*barrier, const void *msg,
						size_t len)
{
    assert(barrier);
    if (msg == NULL || len == 0) {
	barrier->status = EINVAL;
	return;
    }

    struct stat_resolution_barrier *sbarrier =
	(struct stat_resolution_barrier *) barrier;

    struct ctrlmsg_service_stats *smessage =
	(struct ctrlmsg_service_stats *) msg;

    /* not a great mem management tech here */
    memcpy(sbarrier->stats, &smessage->stats, sizeof(smessage->stats));
}

static int get_service_stats(resolution_path * spath,
			     struct service_stat *stats)
{
    assert(spath);

    /* no copying, no resend */
    struct ctrlmsg_service_stats cm;

    memset(&cm, 0, sizeof(cm));
    cm.cmh.type = CTRLMSG_TYPE_SERVICE_STATS;
    cm.cmh.len = sizeof(cm);
    cm.xid = atomic_add_return(1, &spath->path.request_xid);

    struct stat_resolution_barrier barrier;
    bzero(&barrier, sizeof(barrier));
    barrier.stats = stats;

    init_message_barrier(&barrier.barrier, spath,
			 CTRLMSG_TYPE_SERVICE_STATS,
			 resolution_path_handle_success_stat,
			 message_barrier_handle_failure_default, NULL);

    atomic_inc(&barrier.barrier.message_count);

    task_mutex_lock(&spath->path.message_mutex);
    uint32_t *xid = (uint32_t *) malloc(sizeof(*xid));
    *xid = cm.xid;

    g_hash_table_insert(spath->path.message_table, xid, &barrier);
    task_mutex_unlock(&spath->path.message_mutex);

    spath->path.channel->interface->send_message(spath->path.channel, &cm,
						 sizeof(cm));

    /*why does it mutate the path interface??? */
    LOG_DBG("Waiting for service stats response\n");
    wait_for_message_barrier(&barrier.barrier);
    return 0;

}

static int configure_interface(resolution_path * spath, const char *ifname,
			       const struct net_addr *ipaddr,
			       unsigned short flags)
{

    struct ctrlmsg_iface_conf cm;

    if (ifname == NULL) {
	/*should be EINVAL */
	return -1;
    }

    memset(&cm, 0, sizeof(cm));
    cm.cmh.type = CTRLMSG_TYPE_IFACE_CONF;
    cm.cmh.len = sizeof(cm);
    strncpy(cm.ifname, ifname, IFNAMSIZ - 1);
    if (ipaddr)
	memcpy(&cm.ipaddr, ipaddr, sizeof(*ipaddr));
    cm.flags = flags;

    /*async message - send it! */
    int retval =
	spath->path.channel->interface->send_message(spath->path.channel,
						     &cm, sizeof(cm));

    return retval;
}

static int get_resolutions(resolution_path * spath,
			   struct service_desc *service,
			   struct service_info **resolutions)
{
    assert(spath);

    /* no copying, no resend */
    struct ctrlmsg_service cm;
    struct get_resolution_barrier barrier;

    memset(&cm, 0, sizeof(cm));
    cm.cmh.type = CTRLMSG_TYPE_GET_SERVICE;
    cm.cmh.len = sizeof(cm);
    cm.service[0].srvid_flags = service->flags;
    cm.service[0].srvid_prefix_bits = service->prefix;
    cm.xid = atomic_add_return(1, &spath->path.request_xid);

    memcpy(&cm.service[0].srvid, &service->service, sizeof(struct service_id));

    bzero(&barrier, sizeof(barrier));

    init_message_barrier(&barrier.barrier, spath, CTRLMSG_TYPE_GET_SERVICE,
			 resolution_path_handle_success_get,
			 message_barrier_handle_failure_default, NULL);
    atomic_inc(&barrier.barrier.message_count);

    task_mutex_lock(&spath->path.message_mutex);
    uint32_t *xid = (uint32_t *) malloc(sizeof(*xid));
    *xid = cm.xid;

    g_hash_table_insert(spath->path.message_table, xid, &barrier);
    task_mutex_unlock(&spath->path.message_mutex);

    spath->path.channel->interface->send_message(spath->path.channel, &cm,
						 sizeof(cm));

    wait_for_message_barrier(&barrier.barrier);

    *resolutions = barrier.resolutions;
    return barrier.count;

}

static int get_resolutions_async(resolution_path * path,
				 struct service_desc *service,
				 resolution_path_callback callback)
{
    return 0;
}

static int add_resolutions(resolution_path * spath,
			   struct service_info *resolutions, size_t res_count)
{
    assert(spath);
    if (resolutions == NULL) {
	return EINVAL;
    }
    if (res_count == 0) {
	return 0;
    }

    struct ctrlmsg_service cm;
    int batch_size = (MAX_MSG_SIZE - sizeof(cm)) / sizeof(*resolutions);
    int batch_count = res_count / batch_size;
    int count = 0;
    if (res_count % batch_size > 0) {
	batch_count++;
    }

    /* no copying, no resend */
    int size = sizeof(cm) + res_count * sizeof(*resolutions);
    //struct ctrlmsg_service* cm = (struct ctrlmsg_service*) malloc(size);
    LOG_DBG("Adding %zu stack resolution rules, size %i, %zu\n", res_count,
	    size, sizeof(cm));

    //cm.xid = atomic_add_return(1, &spath->request_xid);
    bzero(&cm, sizeof(cm));
    cm.cmh.type = CTRLMSG_TYPE_ADD_SERVICE;

    /*would be better with scatter gather? */
    //    int i = 0;
    //    for(; i < res_count; i++) {
    //        memcpy(&cm->resolution[i], &resolutions[i], sizeof(*resolutions));
    //    }

    struct iovec iov[2] = { {(void *) &cm, sizeof(cm)}
    , {NULL, 0}
    };

    int i = 0, retval = 0, sent = 0;
    for (i = 0; i < batch_count; i++) {
	count = batch_size > res_count ? res_count : batch_size;
	cm.cmh.len = sizeof(cm) + count * sizeof(*resolutions);
	iov[1].iov_base = resolutions + i * batch_size;
	iov[1].iov_len = count * sizeof(*resolutions);
	retval =
	    spath->path.channel->interface->send_message_iov(spath->
							     path.channel, iov,
							     2, cm.cmh.len);

	if (retval <= 0) {
	    //error TODO
	} else {
	    sent += count;
	}
    }

    /* response handled as event
     * TODO - still keep (async) callback to check which resolutions were added?
     * */
    return sent;
}

#if defined(ENABLE_DISABLED)
static int _add_resolutions(resolution_path * spath,
			    struct service_info *resolutions, size_t res_count)
{
    assert(spath);
    if (resolutions == NULL || res_count <= 0) {
	return -1;
    }

    struct ctrlmsg_service cm;

    memset(&cm, 0, sizeof(cm));
    cm.cmh.type = CTRLMSG_TYPE_ADD_SERVICE;
    cm.cmh.len = sizeof(cm);
    int i = 0;

    for (; i < res_count; i++) {

	cm.prefix_bits =
	    resolutions[i].sv_prefix_bits >
	    255 ? 255 : resolutions[i].sv_prefix_bits;
	memcpy(&cm.srvid, &resolutions[i].srvid, sizeof(struct service_id));
	memcpy(&cm.ipaddr, &resolutions[i].address.net_un.un_ip,
	       sizeof(struct in_addr));

	spath->path.channel->interface->send_message(spath->path.channel,
						     &cm, sizeof(cm));
    }

    return 0;
}

static int _remove_resolutions(resolution_path * spath,
			       struct service_info *resolutions,
			       size_t res_count)
{
    assert(spath);
    if (resolutions == NULL || res_count <= 0) {
	return -1;
    }

    struct ctrlmsg_service cm;
    cm.cmh.type = CTRLMSG_TYPE_DEL_SERVICE;
    cm.cmh.len = sizeof(cm);

    memset(&cm, 0, sizeof(cm));

    int i = 0;

    for (; i < res_count; i++) {

	cm.prefix_bits =
	    resolutions[i].sv_prefix_bits >
	    255 ? 255 : resolutions[i].sv_prefix_bits;
	memcpy(&cm.srvid, &resolutions[i].srvid, sizeof(struct service_id));
	memcpy(&cm.ipaddr, &resolutions[i].address.net_un.un_ip,
	       sizeof(struct in_addr));

	/* send message must send or fail then return. it cannot return
	 * incomplete.
	 */
	spath->path.channel->interface->send_message(spath->path.channel,
						     &cm, sizeof(cm));
    }

    return 0;
}
#endif				/* ENABLE_DISABLED */

static int add_resolutions_async(resolution_path * path,
				 struct service_info *resolutions,
				 size_t res_count,
				 resolution_path_callback callback)
{
    return 0;
}

static int remove_resolutions(resolution_path * spath,
			      struct service_info_stat *resolutions,
			      size_t res_count)
{

    assert(spath);
    if (resolutions == NULL) {
	return EINVAL;
    }
    if (res_count == 0) {
	return 0;
    }

    struct ctrlmsg_service cm;

    int batch_size = (MAX_MSG_SIZE - sizeof(cm)) / sizeof(*resolutions);
    int batch_count = res_count / batch_size;
    int count = 0;
    if (res_count % batch_size > 0) {
	batch_count++;
    }

    /* no copying, no resend */
    int size = sizeof(cm) + res_count * sizeof(*resolutions);
    //struct ctrlmsg_service* cm = (struct ctrlmsg_service*) malloc(size);
    LOG_DBG("Removing %zu stack resolution rules, size %i, %zu\n",
	    res_count, size, sizeof(cm));

    //cm.xid = atomic_add_return(1, &spath->request_xid);
    bzero(&cm, sizeof(cm));
    cm.cmh.type = CTRLMSG_TYPE_DEL_SERVICE;

    /*would be better with scatter gather? */
    //    int i = 0;
    //    for(; i < res_count; i++) {
    //        memcpy(&cm->resolution[i], &resolutions[i], sizeof(*resolutions));
    //    }

    struct iovec iov[2] = { {(void *) &cm, sizeof(cm)}
    , {NULL, 0}
    };

    int i = 0, retval = 0, sent = 0;
    for (i = 0; i < batch_count; i++) {
	count = batch_size > res_count ? res_count : batch_size;
	cm.cmh.len = sizeof(cm) + count * sizeof(*resolutions);
	iov[1].iov_base = resolutions + i * batch_size;
	iov[1].iov_len = count * sizeof(*resolutions);
	retval =
	    spath->path.channel->interface->send_message_iov(spath->
							     path.channel, iov,
							     2, cm.cmh.len);

	if (retval <= 0) {
	    //error TODO
	} else {
	    sent += count;
	}
    }

    return sent;

}

static int remove_resolutions_async(resolution_path * path,
				    struct service_info_stat *service,
				    resolution_path_callback callback)
{
    return 0;
}

static void set_capabilities(resolution_path * spath, int capabilities)
{
    assert(spath);
    LOG_DBG("Setting resolution path capabilities: %i\n", capabilities);

    struct ctrlmsg_capabilities cm;
    bzero(&cm, sizeof(cm));
    cm.cmh.type = CTRLMSG_TYPE_CAPABILITIES;
    cm.cmh.len = sizeof(cm);
    cm.capabilities = capabilities;
    //    cm.xid = atomic_add_return(1, &spath->path.request_xid);
    //    struct message_barrier barrier;
    //    bzero(&barrier, sizeof(barrier));
    //
    //    init_message_barrier(spath, &barrier, CTRLMSG_TYPE_SET_TRANSIT,
    //            message_barrier_handle_success_default, message_barrier_handle_failure_default, NULL);
    //    atomic_inc(&barrier.barrier.message_count);
    //    task_mutex_lock(&spath->path.message_mutex);
    //
    //    uint32_t* xid = (uint32_t*) malloc(sizeof(*xid));
    //    *xid = cm.xid;
    //
    //    g_hash_table_insert(spath->path.message_table, xid, &barrier);
    //    task_mutex_unlock(&spath->path.message_mutex);

    spath->path.channel->interface->send_message(spath->path.channel, &cm,
						 sizeof(cm));

    // wait_for_message_barrier(&barrier);

}

static int modify_resolutions(resolution_path * spath,
			      struct service_info *resolutions,
			      size_t res_count)
{
    assert(spath);
    if (resolutions == NULL) {
	return EINVAL;
    }
    if (res_count == 0) {
	return 0;
    }

    LOG_DBG("Modifying %zu stack resolution rules\n", res_count);
    /* no copying, no resend */

    struct ctrlmsg_service cm;

    int batch_size = (MAX_MSG_SIZE - sizeof(cm)) / sizeof(*resolutions);
    int batch_count = res_count / batch_size;
    int count = 0;
    if (res_count % batch_size > 0) {
	batch_count++;
    }

    /* no copying, no resend */
    int size = sizeof(cm) + res_count * sizeof(*resolutions);
    //struct ctrlmsg_service* cm = (struct ctrlmsg_service*) malloc(size);
    LOG_DBG("Modifying %zu stack resolution rules, size %i, %zu\n",
	    res_count, size, sizeof(cm));

    //cm.xid = atomic_add_return(1, &spath->request_xid);
    bzero(&cm, sizeof(cm));
    cm.cmh.type = CTRLMSG_TYPE_MOD_SERVICE;

    /*would be better with scatter gather? */
    //    int i = 0;
    //    for(; i < res_count; i++) {
    //        memcpy(&cm->resolution[i], &resolutions[i], sizeof(*resolutions));
    //    }

    struct iovec iov[2] = { {(void *) &cm, sizeof(cm)}
    , {NULL, 0}
    };

    int i = 0, retval = 0, sent = 0;
    for (i = 0; i < batch_count; i++) {
	count = batch_size > res_count ? res_count : batch_size;
	cm.cmh.len = sizeof(cm) + count * sizeof(*resolutions);
	iov[1].iov_base = resolutions + i * batch_size;
	iov[1].iov_len = count * sizeof(*resolutions);
	retval =
	    spath->path.channel->interface->send_message_iov(spath->
							     path.channel, iov,
							     2, cm.cmh.len);

	if (retval <= 0) {
	    //error TODO
	} else {
	    sent += count;
	}
    }

    return count;

}

static int modify_resolutions_async(resolution_path * path,
				    struct service_info *resolutions,
				    size_t res_count,
				    resolution_path_callback callback)
{
    return 0;
}

static void handle_register_message(resolution_path * spath,
				    struct ctrlmsg_register *message,
				    size_t length)
{
    assert(spath);
    LOG_DBG("Handling stack-local register: SID(%i:%i) %s\n",
	    message->srvid_flags, message->srvid_prefix_bits,
	    service_id_to_str(&message->srvid));

    if (spath->path.path_callback.target) {
	struct service_desc sdesc;
	sdesc.flags = message->srvid_flags;
	sdesc.prefix = message->srvid_prefix_bits;

	memcpy(&sdesc.service, &message->srvid, sizeof(struct service_id));
	spath->path.path_callback.service_registered(&spath->path.path_callback,
						     &sdesc);
    }
}

static void handle_unregister_message(resolution_path * spath,
				      struct ctrlmsg_register *message,
				      size_t length)
{
    assert(spath);
    LOG_DBG("Handling stack-local unregister: SID(%i:%i) %s\n",
	    message->srvid_flags, message->srvid_prefix_bits,
	    service_id_to_str(&message->srvid));
    if (spath->path.path_callback.target) {
	struct service_desc sdesc;
	sdesc.flags = message->srvid_flags;
	sdesc.prefix = message->srvid_prefix_bits;
	memcpy(&sdesc.service, &message->srvid, sizeof(struct service_id));
	spath->path.path_callback.service_unregistered(&spath->
						       path.path_callback,
						       &sdesc);
    }
}

static void handle_resolve_message(resolution_path * spath,
				   struct ctrlmsg_resolve *message,
				   size_t length)
{
    assert(spath);
    /*note that the resolve message could/should include src SID and IP and TODO */
    LOG_DBG("Handling resolve: src SID(%i:%i) %s dst SID(%i:%i) %s\n",
	    message->src_flags, message->src_prefix_bits,
	    service_id_to_str(&message->src_srvid), message->dst_flags,
	    message->dst_prefix_bits, service_id_to_str(&message->dst_srvid));

}

static void handle_resolution_removed(resolution_path * spath, struct ctrlmsg_service_stats
				      *message, size_t length)
{
    assert(spath);
    /*TODO - big assumption that the resolutions here include stats */
    int rcount = CTRLMSG_SERVICE_STAT_NUM(message);
    LOG_DBG("Handling resolution removed: %i\n", rcount);

    if (rcount <= 0) {
	LOG_ERR
	    ("Invalid resolution stats in remove message! len: %zu / %zu\n",
	     length, sizeof(struct service_info_stat));
    }
    if (spath->path.path_callback.target) {

	spath->path.path_callback.stat_update(&spath->path.path_callback,
					      (struct service_info_stat *)
					      &message->stats, rcount);

	//        stat_response resp;
	//                resp.count = rcount;
	//                resp.type = SVS_INSTANCE_STATS;
	//                /*TODO this is rather dangerous to assume - full binary compatibilitye between service_info_stat == sv_instance_stats*/
	//                resp.data = (uint8_t*) &message->resolution;
	//spath->path.resolver.interface->update_services(spath->path.resolver.target, NULL,
	//        SVS_INSTANCE_STATS, &resp);
    }
}

static void handle_resolution_added(resolution_path * spath,
				    struct ctrlmsg_service *message,
				    size_t length)
{
    assert(spath);
    /*DO NOTHING for now - may need to verify actual resolutions added TODO */
    LOG_DBG("Handling resolution added: %zu\n", CTRLMSG_SERVICE_NUM(message));
}

static void handle_resolution_modified(resolution_path * spath,
				       struct ctrlmsg_service *message,
				       size_t length)
{
    /*DO NOTHING for now TODO */
    assert(spath);
    LOG_DBG("Handling resolution modified: %zu\n", length);
}

static int resolution_path_message_channel_cb(message_channel_callback *
					      cb, const void *message,
					      size_t length)
{
    assert(cb);

    resolution_path *spath = (resolution_path *) cb->target;
    struct ctrlmsg *cmsg = (struct ctrlmsg *) message;
    struct ctrlmsg_service *amsg;
    struct message_barrier *barrier = NULL;

    LOG_DBG("Recevied stack message of type %i\n", cmsg->type);

    switch (cmsg->type) {
    case CTRLMSG_TYPE_REGISTER:
	handle_register_message(spath, (struct ctrlmsg_register *) message,
				length);
	break;
    case CTRLMSG_TYPE_UNREGISTER:
	handle_unregister_message(spath,
				  (struct ctrlmsg_register *) message, length);
	break;
    case CTRLMSG_TYPE_RESOLVE:
	handle_resolve_message(spath, (struct ctrlmsg_resolve *) message,
			       length);
	break;
    case CTRLMSG_TYPE_ADD_SERVICE:
	handle_resolution_added(spath, (struct ctrlmsg_service *) message,
				length);
	break;
    case CTRLMSG_TYPE_DEL_SERVICE:
	handle_resolution_removed(spath,
				  (struct ctrlmsg_service_stats *) message,
				  length);
	break;
    case CTRLMSG_TYPE_MOD_SERVICE:
	handle_resolution_modified(spath,
				   (struct ctrlmsg_service *) message, length);
	break;
    case CTRLMSG_TYPE_GET_SERVICE:
    case CTRLMSG_TYPE_SERVICE_STATS:
	//case CTRLMSG_TYPE_SET_TRANSIT:
	task_mutex_lock(&spath->path.message_mutex);

	/* TODO although it's a bit dangerous to cast solely to the resolution message,
	 * the xid is in the same field position
	 */
	amsg = (struct ctrlmsg_service *) message;
	barrier =
	    (struct message_barrier *) g_hash_table_lookup(spath->
							   path.message_table,
							   &amsg->xid);

	if (barrier == NULL) {
	    task_mutex_unlock(&spath->path.message_mutex);
	    LOG_ERR("Resolution response received for unknown request: %u",
		    amsg->xid);
	} else {
	    g_hash_table_remove(spath->path.message_table, &amsg->xid);
	    task_mutex_unlock(&spath->path.message_mutex);
	    message_barrier_default_cb(barrier, cmsg->type, message, length);
	}
	break;
    }

    return 0;
}
