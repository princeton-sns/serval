/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <libservalctrl/hostctrl.h>
#include <serval/ctrlmsg.h>
#include <netinet/serval.h>
#include <stdlib.h>
#include <string.h>
#include "hostctrl_ops.h"

static int local_service_add(struct hostctrl *hc,
                             const struct service_id *srvid, 
                             unsigned short prefix_bits,
                             const struct in_addr *ipaddr)
{
	struct {
		struct ctrlmsg_service cm;
		struct service_info service;
	} req;

        if (!srvid)
                return -1;

        memset(&req, 0, sizeof(req));
        req.cm.cmh.type = CTRLMSG_TYPE_ADD_SERVICE;
        req.cm.cmh.len = CTRLMSG_SERVICE_NUM_LEN(1);
	req.cm.service[0].srvid_prefix_bits = 
                (prefix_bits > SERVICE_ID_MAX_PREFIX_BITS) ?
                0 : prefix_bits;
        memcpy(&req.cm.service[0].srvid, srvid, sizeof(*srvid));
        memcpy(&req.cm.service[0].address, ipaddr, sizeof(*ipaddr));
	/* strncpy(req.cm.ifname, ifname, IFNAMSIZ - 1); */
        
        LOG_DBG("prefix_bits=%u len=%u sizeof(req)=%zu %lu %s\n",
		req.cm.service[0].srvid_prefix_bits, 
		CTRLMSG_SERVICE_LEN(&req.cm), sizeof(req), 
		CTRLMSG_SERVICE_NUM(&req.cm),
		service_id_to_str(&req.cm.service[0].srvid));

	return message_channel_send(hc->mc, &req.cm, req.cm.cmh.len);
}

static int local_service_remove(struct hostctrl *hc, 
                                const struct service_id *srvid,
                                unsigned short prefix_bits,
                                const struct in_addr *ipaddr)
{
	struct {
		struct ctrlmsg_service cm;
		struct service_info service;
	} req;

        if (!srvid)
                return -1;

        memset(&req, 0, sizeof(req));
        req.cm.cmh.type = CTRLMSG_TYPE_DEL_SERVICE;
        req.cm.cmh.len = CTRLMSG_SERVICE_NUM_LEN(1);
        req.cm.service[0].srvid_prefix_bits = 
                (prefix_bits > SERVICE_ID_MAX_PREFIX_BITS) ? 
                0 : prefix_bits;
        memcpy(&req.cm.service[0].srvid, srvid, sizeof(*srvid));
	
        if (ipaddr) {
                memcpy(&req.cm.service[0].address, ipaddr, sizeof(*ipaddr));
        }
	/* strncpy(cm.ifname, ifname, IFNAMSIZ - 1); */
        
        return message_channel_send(hc->mc, &req.cm, req.cm.cmh.len);
}

static int local_service_register_dummy(struct hostctrl *hc, 
                                        const struct service_id *srvid,
                                        unsigned short prefix_bits)
{
        return 0;
}

static int local_interface_migrate(struct hostctrl *hc,
                                   const char *from_iface,
                                   const char *to_iface)
{
        struct ctrlmsg_migrate cm;

        if (!from_iface || !to_iface) {
                LOG_ERR("Undefined interface\n");
                return -1;
        }
        
        memset(&cm, 0, sizeof(cm));
        cm.cmh.type = CTRLMSG_TYPE_MIGRATE;
        cm.cmh.len = sizeof(cm);
        cm.migrate_type = CTRL_MIG_IFACE;
        strncpy(cm.from_i, from_iface, IFNAMSIZ - 1);
        strncpy(cm.to_i, to_iface, IFNAMSIZ - 1);
        
        return message_channel_send(hc->mc, &cm, cm.cmh.len);
}

static int local_flow_migrate(struct hostctrl *hc,
                              struct flow_id *flow,
                              const char *to_iface)
{
        struct ctrlmsg_migrate cm;

        if (!flow) {
                LOG_ERR("Undefined flow\n");
                return -1;
        }

        if (!to_iface) {
                LOG_ERR("Undefined interface\n");
                return -1;
        }

        memset(&cm, 0, sizeof(cm));
        cm.cmh.type = CTRLMSG_TYPE_MIGRATE;
        cm.cmh.len = sizeof(cm);
        cm.migrate_type = CTRL_MIG_FLOW;
        memcpy(&cm.from_f, flow, sizeof(struct flow_id));
        strncpy(cm.to_i, to_iface, IFNAMSIZ - 1);

        return message_channel_send(hc->mc, &cm, cm.cmh.len);
}

static int local_service_migrate(struct hostctrl *hc,
                                 struct service_id *srvid,
                                 const char *to_iface)
{
        struct ctrlmsg_migrate cm;

        if (!srvid) {
                LOG_ERR("Undefined service\n");
                return -1;
        }

        if (!to_iface) {
                LOG_ERR("Undefined interface\n");
                return -1;
        }

        memset(&cm, 0, sizeof(cm));
        cm.cmh.type = CTRLMSG_TYPE_MIGRATE;
        cm.cmh.len = sizeof(cm);
        cm.migrate_type = CTRL_MIG_SERVICE;
        memcpy(&cm.from_s, srvid, sizeof(struct service_id));
        strncpy(cm.to_i, to_iface, IFNAMSIZ - 1);

        return message_channel_send(hc->mc, &cm, cm.cmh.len);
}

int local_ctrlmsg_recv(struct hostctrl *hc, struct ctrlmsg *cm, 
                       struct in_addr *from)
{
        int ret = 0;
        
        switch (cm->type) {
        case CTRLMSG_TYPE_REGISTER:
                ret = handle_service_change(hc, (struct ctrlmsg_register *)cm,
                                            from,
                                            hc->cbs->service_registration);
                break;
        case CTRLMSG_TYPE_UNREGISTER:
                ret = handle_service_change(hc, (struct ctrlmsg_register *)cm,
                                            from,
                                            hc->cbs->service_unregistration);
                break;
        case CTRLMSG_TYPE_RESOLVE:
                break;
        case CTRLMSG_TYPE_SERVICE_STAT:
                break;
        case CTRLMSG_TYPE_ADD_SERVICE:
                break;
        case CTRLMSG_TYPE_DEL_SERVICE:
                break;
	default:
		LOG_DBG("Received message type %u\n", cm->type);
		break;
	}
        
        return ret;
}

struct hostctrl_ops local_ops = {
        .interface_migrate = local_interface_migrate,
        .flow_migrate = local_flow_migrate,
        .service_migrate = local_service_migrate,
        .service_register = local_service_register_dummy,
        .service_unregister = local_service_register_dummy,
	.service_add = local_service_add,
	.service_remove = local_service_remove,
        .ctrlmsg_recv = local_ctrlmsg_recv,
};
