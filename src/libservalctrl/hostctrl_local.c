/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <libservalctrl/hostctrl.h>
#include <serval/ctrlmsg.h>
#include <netinet/serval.h>
#include <stdlib.h>
#include <string.h>
#include "hostctrl_ops.h"

static int local_service_generic(struct hostctrl *hc, int type,
                                 const struct service_id *srvid, 
                                 unsigned short prefix_bits,
                                 unsigned int priority,
                                 unsigned int weight,
                                 const struct in_addr *ipaddr)
{
    struct {
		struct ctrlmsg_service cm;
		struct service_info service;
	} req;

    if (!srvid)
        return -1;

    memset(&req, 0, sizeof(req));
    req.cm.cmh.type = type;
    req.cm.cmh.xid = ++hc->xid;
    req.cm.cmh.len = CTRLMSG_SERVICE_NUM_LEN(1);
	req.cm.service[0].srvid_prefix_bits = 
        (prefix_bits > SERVICE_ID_MAX_PREFIX_BITS) ?
        0 : prefix_bits;
    req.cm.service[0].priority = priority;
    req.cm.service[0].weight = weight;
    memcpy(&req.cm.service[0].srvid, srvid, sizeof(*srvid));

    if (ipaddr)
        memcpy(&req.cm.service[0].address, ipaddr, sizeof(*ipaddr));
        
    req.cm.service[0].if_index = -1;

	/* strncpy(req.cm.ifname, ifname, IFNAMSIZ - 1); */
        
    LOG_DBG("op=%d prefix_bits=%u len=%u sizeof(req)=%zu %zu %s\n",      
            type, req.cm.service[0].srvid_prefix_bits, 
            CTRLMSG_SERVICE_LEN(&req.cm), sizeof(req), 
            CTRLMSG_SERVICE_NUM(&req.cm),
            service_id_to_str(&req.cm.service[0].srvid));

	return message_channel_send(hc->mc, &req.cm, req.cm.cmh.len);
}
                                 
static int local_service_add(struct hostctrl *hc,
                             const struct service_id *srvid, 
                             unsigned short prefix_bits,
                             unsigned int priority,
                             unsigned int weight,
                             const struct in_addr *ipaddr)
{
	return local_service_generic(hc, CTRLMSG_TYPE_ADD_SERVICE,
                                 srvid, prefix_bits, priority, 
                                 weight, ipaddr);
}

static int local_service_remove(struct hostctrl *hc, 
                                const struct service_id *srvid,
                                unsigned short prefix_bits,
                                const struct in_addr *ipaddr)
{
	return local_service_generic(hc, CTRLMSG_TYPE_DEL_SERVICE,
                                 srvid, prefix_bits, 0, 0, ipaddr);
}

static int local_service_modify(struct hostctrl *hc, 
                                const struct service_id *srvid,
                                unsigned short prefix_bits,
                                unsigned int priority,
                                unsigned int weight,
                                const struct in_addr *old_ip,
                                const struct in_addr *new_ip)
{
	struct {
		struct ctrlmsg_service cm;
		struct service_info service[2];
	} req;

    if (!srvid || !old_ip)
        return -1;

    memset(&req, 0, sizeof(req));
    req.cm.cmh.type = CTRLMSG_TYPE_MOD_SERVICE;
    req.cm.cmh.len = CTRLMSG_SERVICE_NUM_LEN(2);
    req.cm.cmh.xid = ++hc->xid;
    req.service[0].srvid_prefix_bits = 
        (prefix_bits > SERVICE_ID_MAX_PREFIX_BITS) ? 
        0 : prefix_bits;
    req.service[0].priority = priority;
    req.service[0].weight = weight;
    memcpy(&req.service[0].srvid, srvid, sizeof(*srvid));
    memcpy(&req.service[0].address, old_ip, sizeof(*old_ip));

    req.service[0].if_index = -1;
    req.service[1].if_index = -1;

    if (!new_ip)
        memcpy(&req.service[1].address, old_ip, sizeof(*old_ip));
    else
        memcpy(&req.service[1].address, new_ip, sizeof(*new_ip));

	/* strncpy(cm.ifname, ifname, IFNAMSIZ - 1); */
        
    return message_channel_send(hc->mc, &req.cm, req.cm.cmh.len);
}

static int local_service_get(struct hostctrl *hc, 
                             const struct service_id *srvid,
                             unsigned short prefix_bits,
                             const struct in_addr *ipaddr)
{
	return local_service_generic(hc, CTRLMSG_TYPE_GET_SERVICE,
                                 srvid, prefix_bits, 0, 0, ipaddr);
}

static int local_service_register_dummy(struct hostctrl *hc, 
                                        const struct service_id *srvid,
                                        unsigned short prefix_bits,
                                        const struct in_addr *old_ip)
{
    return 0;
}

static int local_service_unregister_dummy(struct hostctrl *hc, 
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
    cm.cmh.xid = ++hc->xid;
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
    cm.cmh.xid = ++hc->xid;
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
    cm.cmh.xid = ++hc->xid;
    cm.migrate_type = CTRL_MIG_SERVICE;
    memcpy(&cm.from_s, srvid, sizeof(struct service_id));
    strncpy(cm.to_i, to_iface, IFNAMSIZ - 1);

    return message_channel_send(hc->mc, &cm, cm.cmh.len);
}

int local_ctrlmsg_recv(struct hostctrl *hc, struct ctrlmsg *cm, 
                       struct sockaddr *from, socklen_t from_len)
{
    struct in_addr local_ip;
    int ret = 0;

    if (!hc->cbs)
        return 0;
    
    memset(&local_ip, 0, sizeof(local_ip));
  
    if (from) {
        if (from->sa_family == AF_INET)
            memcpy(&local_ip, &((struct sockaddr_in *)from)->sin_addr, 
                   sizeof(local_ip));
        else if (from->sa_family == AF_SERVAL && 
                 from_len > sizeof(struct sockaddr_in)) {
            channel_addr_t *addr = (channel_addr_t *)from;
            
            if (addr->sv_in.in.sin_family == AF_INET) {
                memcpy(&local_ip, &addr->sv_in.in.sin_addr, 
                       sizeof(local_ip));
            }
        }
    }
    
    switch (cm->type) {
    case CTRLMSG_TYPE_REGISTER: {
        struct ctrlmsg_register *cmr = (struct ctrlmsg_register *)cm;
        ret = hc->cbs->service_registration(hc,
                                            &cmr->srvid, 
                                            cmr->srvid_flags, 
                                            cmr->srvid_prefix_bits, 
                                            &local_ip, NULL);
        break;
    }
    case CTRLMSG_TYPE_UNREGISTER: {
        struct ctrlmsg_register *cmr = (struct ctrlmsg_register *)cm;
        ret = hc->cbs->service_unregistration(hc, 
                                              &cmr->srvid, 
                                              cmr->srvid_flags, 
                                              cmr->srvid_prefix_bits, 
                                              &local_ip);
        break;
    }
    case CTRLMSG_TYPE_RESOLVE:                
        break;
    case CTRLMSG_TYPE_GET_SERVICE: {
        struct ctrlmsg_service *cs = 
            (struct ctrlmsg_service *)cm;

        if (hc->cbs->service_get_result)
            ret = hc->cbs->service_get_result(hc, 
                                              cm->xid,
                                              cm->retval,
                                              &cs->service[0], 
                                              CTRLMSG_SERVICE_NUM(cs));
        break;
    }
    case CTRLMSG_TYPE_SERVICE_STAT: {
        struct ctrlmsg_service_stat *css = 
            (struct ctrlmsg_service_stat *)cm;
                
        if (hc->cbs->service_stat_update)
            ret = hc->cbs->service_stat_update(hc,
                                               cm->xid,
                                               cm->retval,
                                               &css->stats, 
                                               CTRLMSG_SERVICE_STAT_NUM(css));
        break;
    }
    case CTRLMSG_TYPE_ADD_SERVICE: {
        struct ctrlmsg_service *cs = 
            (struct ctrlmsg_service *)cm;

        if (hc->cbs->service_add_result)
            ret = hc->cbs->service_add_result(hc, 
                                              cm->xid,
                                              cm->retval,
                                              &cs->service[0], 
                                              CTRLMSG_SERVICE_NUM(cs));
        break;
    }
    case CTRLMSG_TYPE_MOD_SERVICE: {
        struct ctrlmsg_service *cs = 
            (struct ctrlmsg_service *)cm;

        if (hc->cbs->service_mod_result)
            ret = hc->cbs->service_mod_result(hc,
                                              cm->xid,
                                              cm->retval,
                                              &cs->service[0], 
                                              CTRLMSG_SERVICE_NUM(cs));
        break;
    }
    case CTRLMSG_TYPE_DEL_SERVICE: {
        struct ctrlmsg_service_info_stat *csis = 
            (struct ctrlmsg_service_info_stat *)cm;

        if (hc->cbs->service_remove_result)
            ret = hc->cbs->service_remove_result(hc,
                                                 cm->xid,
                                                 cm->retval,
                                                 &csis->service[0], 
                                                 CTRLMSG_SERVICE_INFO_STAT_NUM(csis));
        break;
    }
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
    .service_unregister = local_service_unregister_dummy,
	.service_add = local_service_add,
	.service_remove = local_service_remove,
	.service_modify = local_service_modify,
    .service_get = local_service_get,
    .ctrlmsg_recv = local_ctrlmsg_recv,
};
