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

//struct sv_resolution_path;

//TODO - add a field (get/set) for a resolver for reg/unreg/resolve callbacks?
typedef struct sv_path_callback {
    void* target;
    void (*resolution_path_cb)(void* target, uint32_t xid, uint16_t status, void* data);
} resolution_path_callback;

struct sv_resolution_path_interface {
    int (* initialize)(void* path);
    void (* start)(void* path);
    void (* stop)(void* path);
    int (* finalize)(void* path);

    void (*set_resolver)(void* target, service_resolver* resolver);
    const service_resolver* (*get_resolver)(void* target);

    int (*configure_interface)(void* path, const char *ifname, const struct net_addr *ipaddr,
            unsigned short flags);

    int (*get_service_stats) (void* path, struct service_stat* stats);
    void (*set_transit) (void* path, int transit);

    int (* get_resolutions)(void* path, struct service_desc* service,
            struct service_resolution**resolutions);
    int (* get_resolutions_async)(void* path, struct service_desc* service,
            resolution_path_callback callback);

    int (* add_resolutions)(void* path, struct service_resolution* resolutions, size_t res_count);
    int (* add_resolutions_async)(void* path, struct service_resolution* resolutions,
            size_t res_count, resolution_path_callback callback);

    int (* remove_resolutions)(void* path, struct service_resolution_stat* service, size_t res_count);
    int (* remove_resolutions_async)(void* path, struct service_resolution_stat* service,
            resolution_path_callback callback);

    int
    (* modify_resolutions)(void* path, struct service_resolution* resolutions, size_t res_count);
    int (* modify_resolutions_async)(void* path, struct service_resolution* resolutions,
            size_t res_count, resolution_path_callback callback);

    //to-kernel messages
    //CTRLMSG_TYPE_IFACE_CONF = 100,
    //CTRLMSG_TYPE_SET_SERVICE = 101,
};

typedef struct {
    void* target;
    struct sv_resolution_path_interface* interface;
} resolution_path;

//callbacks - straight through the resolver interface - though not the
#endif /* RESOLUTION_PATH_H_ */
