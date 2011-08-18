/*
 * service_path.h
 *
 *  Created on: Feb 9, 2011
 *      Author: daveds
 */

#ifndef RESOLUTION_PATH_H_
#define RESOLUTION_PATH_H_

#include <netinet/serval.h>
#include "libstack/ctrlmsg.h"
#include "resolver.h"
#include "service_types.h"
#include <glib.h>

#include "message_channel.h"
#include "task.h"

#define MAX_MSG_SIZE 2048
//struct sv_resolution_path;

//TODO - add a field (get/set) for a resolver for reg/unreg/resolve callbacks?
typedef struct sv_path_async_callback {
    void *target;
    void (*resolution_path_cb) (struct sv_path_async_callback * target,
				uint32_t xid, uint16_t status, void *data);
} resolution_path_async_callback;

typedef struct sv_path_callback {
    void *target;
    int (*service_registered) (struct sv_path_callback * target,
			       struct service_desc * service);
    int (*service_unregistered) (struct sv_path_callback * target,
				 struct service_desc * service);
    int (*stat_update) (struct sv_path_callback * target,
			struct service_info_stat * res_stats, size_t scount);
    int (*resolve_service) (struct sv_path_callback * target,
			    struct service_desc * service,
			    struct net_addr * address);
    //two more callback funcs for modified/added TODO
} resolution_path_callback;


struct sv_resolution_path {
    enum component_state state;
    int stack_id;
    atomic_t request_xid;
    GHashTable *message_table;
    task_mutex message_mutex;
    task_cond message_cond;

    /*callback for incoming events/queries */
    resolution_path_callback path_callback;
    /*stack-message channel - netlink or unix */
    message_channel *channel;
    /*stack-message callback */
    message_channel_callback callback;

};

typedef struct {
    struct sv_resolution_path path;
    struct sv_resolution_path_interface *interface;
} resolution_path;

struct sv_resolution_path_interface {
    int (*initialize) (resolution_path * path);
    void (*start) (resolution_path * path);
    void (*stop) (resolution_path * path);
    int (*finalize) (resolution_path * path);

    void (*set_path_callback) (resolution_path * target,
			       resolution_path_callback * resolver);
    const resolution_path_callback *(*get_path_callback) (resolution_path *
							  target);

    int (*configure_interface) (resolution_path * path, const char *ifname,
				const struct net_addr * ipaddr,
				unsigned short flags);

    int (*get_service_stats) (resolution_path * path,
			      struct service_stat * stats);
    void (*set_capabilities) (resolution_path * path, int capabilities);

    int (*get_resolutions) (resolution_path * path,
			    struct service_desc * service,
			    struct service_info ** resolutions);
    int (*get_resolutions_async) (resolution_path * path,
				  struct service_desc * service,
				  resolution_path_callback callback);

    int (*add_resolutions) (resolution_path * path,
			    struct service_info * resolutions,
			    size_t res_count);
    int (*add_resolutions_async) (resolution_path * path,
				  struct service_info * resolutions,
				  size_t res_count,
				  resolution_path_callback callback);

    int (*remove_resolutions) (resolution_path * path,
			       struct service_info_stat * service,
			       size_t res_count);
    int (*remove_resolutions_async) (resolution_path * path,
				     struct service_info_stat * service,
				     resolution_path_callback callback);

    int
     (*modify_resolutions) (resolution_path * path,
			    struct service_info * resolutions,
			    size_t res_count);
    int (*modify_resolutions_async) (resolution_path * path,
				     struct service_info * resolutions,
				     size_t res_count,
				     resolution_path_callback callback);

    //to-kernel messages
    //CTRLMSG_TYPE_IFACE_CONF = 100,
    //CTRLMSG_TYPE_SET_SERVICE = 101,
};

//callbacks - straight through the resolver interface - though not the
#endif				/* RESOLUTION_PATH_H_ */
