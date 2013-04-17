/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <libservalctrl/hostctrl.h>
#include <serval/ctrlmsg.h>
#include <netinet/serval.h>
#include <stdlib.h>
#include <string.h>
#include "hostctrl_ops.h"

static int local_service_generic(struct hostctrl *hc,
                                 unsigned short msgtype,
                                 enum service_rule_type ruletype,
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
    req.cm.cmh.type = msgtype;
    req.cm.cmh.xid = ++hc->xid;
    req.cm.cmh.len = CTRLMSG_SERVICE_NUM_LEN(1);
    req.cm.service[0].type = ruletype;
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
            msgtype, req.cm.service[0].srvid_prefix_bits, 
            CTRLMSG_SERVICE_LEN(&req.cm), sizeof(req), 
            CTRLMSG_SERVICE_NUM(&req.cm),
            service_id_to_str(&req.cm.service[0].srvid));

	return message_channel_send(hc->mc, &req.cm, req.cm.cmh.len);
}
                                 
static int local_service_add(struct hostctrl *hc,
                             enum service_rule_type type,
                             const struct service_id *srvid, 
                             unsigned short prefix_bits,
                             unsigned int priority,
                             unsigned int weight,
                             const struct in_addr *ipaddr)
{
	return local_service_generic(hc, CTRLMSG_TYPE_ADD_SERVICE,
                                 type, srvid, prefix_bits, priority, 
                                 weight, ipaddr);
}

static int local_service_remove(struct hostctrl *hc, 
                                enum service_rule_type type,
                                const struct service_id *srvid,
                                unsigned short prefix_bits,
                                const struct in_addr *ipaddr)
{
	return local_service_generic(hc, CTRLMSG_TYPE_DEL_SERVICE, 
                                 type, srvid, prefix_bits, 
                                 0, 0, ipaddr);
}

static int local_service_modify(struct hostctrl *hc, 
                                enum service_rule_type type,
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

    if (!srvid)
        return -1;

    memset(&req, 0, sizeof(req));
    req.cm.cmh.type = CTRLMSG_TYPE_MOD_SERVICE;
    req.cm.cmh.len = CTRLMSG_SERVICE_NUM_LEN(2);
    req.cm.cmh.xid = ++hc->xid;
    req.service[0].type = type;
    req.service[0].srvid_prefix_bits = 
        (prefix_bits > SERVICE_ID_MAX_PREFIX_BITS) ? 
        0 : prefix_bits;
    req.service[0].priority = priority;
    req.service[0].weight = weight;
    memcpy(&req.service[0].srvid, srvid, sizeof(*srvid));

    if (old_ip)
        memcpy(&req.service[0].address, old_ip, sizeof(*old_ip));

    req.service[0].if_index = -1;
    req.service[1].if_index = -1;

    if (!new_ip && old_ip)
        memcpy(&req.service[1].address, old_ip, sizeof(*old_ip));
    else if (new_ip)
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
                                 SERVICE_RULE_UNDEFINED, srvid, prefix_bits, 
                                 0, 0, ipaddr);
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

static int local_flow_stats_query(struct hostctrl *hc,
                                  struct flow_id *flowids, int flows)
{
        int size = sizeof(struct ctrlmsg) + flows * sizeof(struct flow_id);
        struct ctrlmsg_stats_query *cm = malloc(size);
        int i = 0;

        if (!cm) {
                LOG_ERR("Could not allocate message\n");
                return -1;
        }

        memset(cm, 0, size);
        cm->cmh.type = CTRLMSG_TYPE_STATS_QUERY;
        cm->cmh.len = size;
        for (i = 0; i < flows; i++) {
                memcpy(&cm->flows[i], &flowids[i], sizeof(struct flow_id));
        }

        return message_channel_send(hc->mc, cm, cm->cmh.len);
}

static int local_service_delay_verdict(struct hostctrl *hc,
                                       unsigned int pkt_id,
                                       enum delay_verdict verdict)
{
    struct ctrlmsg_delay cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.cmh.type = CTRLMSG_TYPE_DELAY_VERDICT;
    cmd.cmh.len = sizeof(cmd);
    cmd.cmh.xid = ++hc->xid;
    cmd.pkt_id = pkt_id;
    cmd.verdict = verdict;
    
    return message_channel_send(hc->mc, &cmd.cmh, cmd.cmh.len);
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
    case CTRLMSG_TYPE_STATS_RESP: {
        struct ctrlmsg_stats_response *csr = (struct ctrlmsg_stats_response*)cm;
        if (hc->cbs->flow_stat_update)
            ret = hc->cbs->flow_stat_update(hc, cm->xid, cm->retval, csr);
        break;
    }
    case CTRLMSG_TYPE_DELAY_NOTIFY: {
        struct ctrlmsg_delay *cmd = 
            (struct ctrlmsg_delay *)cm;
        if (hc->cbs->service_delay_notification)
            ret = hc->cbs->service_delay_notification(hc,
                                                      cm->xid,
                                                      cmd->pkt_id,
                                                      &cmd->service);
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
    .flow_stats_query = local_flow_stats_query,
    .service_register = local_service_register_dummy,
    .service_unregister = local_service_unregister_dummy,
	.service_add = local_service_add,
	.service_remove = local_service_remove,
	.service_modify = local_service_modify,
    .service_get = local_service_get,
    .service_delay_verdict = local_service_delay_verdict,
    .ctrlmsg_recv = local_ctrlmsg_recv,
};
