/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <libstack/ctrlmsg.h>
#include <libstack/callback.h>
#include <serval/platform.h>
#include <event.h>
#include <string.h>
#include "debug.h"

extern struct libstack_callbacks *callbacks;
extern int eventloop_init(void);
extern void eventloop_fini(void);
extern void unix_init(void);
extern void unix_fini(void);
#if defined(OS_LINUX)
extern void netlink_init(void);
extern void netlink_fini(void);
#endif

int libstack_migrate_interface(const char *from_if,
		                       const char *to_if)
{
	    struct ctrlmsg_migrate cm;

	    if (!from_if || !to_if) {
                LOG_ERR("Undefined interface\n");
	    	return -1;
            }

	    memset(&cm, 0, sizeof(cm));
	    cm.cmh.type = CTRLMSG_TYPE_MIGRATE;
	    cm.cmh.len = sizeof(cm);
	    strncpy(cm.from_if, from_if, IFNAMSIZ - 1);
	    strncpy(cm.to_if, to_if, IFNAMSIZ - 1);

	    return event_sendmsg(&cm, cm.cmh.len);
}

int libstack_add_service(const struct service_id *srvid,
                         unsigned int prefix_bits,
                         const struct in_addr *ipaddr)
{
        struct ctrlmsg_service cm;

        if (!srvid)
                return -1;

        memset(&cm, 0, sizeof(cm));
        cm.cmh.type = CTRLMSG_TYPE_ADD_SERVICE;
        cm.cmh.len = sizeof(cm);
        cm.service[0].srvid_prefix_bits = 
                (prefix_bits > SERVICE_ID_MAX_PREFIX_BITS) ?
                SERVICE_ID_MAX_PREFIX_BITS : prefix_bits;
        memcpy(&cm.service[0].srvid, srvid, sizeof(*srvid));
        memcpy(&cm.service[0].address, ipaddr, sizeof(*ipaddr));
	/* strncpy(cm.ifname, ifname, IFNAMSIZ - 1); */
        
        LOG_DBG("prefix_bits=%u\n", cm.service[0].srvid_prefix_bits);
        return event_sendmsg(&cm, cm.cmh.len);
}

int libstack_del_service(const struct service_id *srvid,
                         unsigned int prefix_bits,
                         const struct in_addr *ipaddr)
{
        struct ctrlmsg_service cm;

        if (!srvid)
                return -1;

        memset(&cm, 0, sizeof(cm));
        cm.cmh.type = CTRLMSG_TYPE_DEL_SERVICE;
        cm.cmh.len = CTRLMSG_SERVICE_LEN(1);
        cm.service[0].srvid_prefix_bits = 
                (prefix_bits > SERVICE_ID_MAX_PREFIX_BITS) ? 
                SERVICE_ID_MAX_PREFIX_BITS : prefix_bits;
        memcpy(&cm.service[0].srvid, srvid, sizeof(*srvid));

        if (ipaddr) {
                memcpy(&cm.service[0].address, ipaddr, sizeof(*ipaddr));
        }
	/* strncpy(cm.ifname, ifname, IFNAMSIZ - 1); */
        
        return event_sendmsg(&cm, cm.cmh.len);
}

int libstack_register_callbacks(struct libstack_callbacks *calls)
{
	if (callbacks) {
                LOG_ERR("Failed: callbacks already set\n");
                return -1;
        }
        if (!calls) {
                LOG_ERR("Bad argument.\n");
                return -1;
        }
        LOG_DBG("registered callbacks\n");
	callbacks = calls;
	
	return 0;
}

void libstack_unregister_callbacks(struct libstack_callbacks *calls)
{
	if (callbacks == calls)
		callbacks = NULL;
}

int libstack_init(void)
{
        unix_init();
#if defined(OS_LINUX)
        netlink_init();
#endif
	return eventloop_init();
}

void libstack_fini(void) 
{
	eventloop_fini();

#if defined(OS_LINUX)
        netlink_fini();
#endif
        unix_fini();

}
