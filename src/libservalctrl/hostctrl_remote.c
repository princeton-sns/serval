/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <libservalctrl/hostctrl.h>
#include <serval/ctrlmsg.h>
#include <netinet/serval.h>
#include <stdlib.h>
#include <string.h>
#include "hostctrl_ops.h"

/*
  When sending a service registration message, the IP being registered
  is actually the IP address in the source field of the IP header. We
  only need to pass the old IP in the registration message in case we
  are re-registering.
*/
static int remote_service_register(struct hostctrl *hc,
                                   const struct service_id *srvid, 
                                   unsigned short prefix_bits,
                                   const struct in_addr *old_ip)
{
    struct ctrlmsg_register req;

    if (!srvid)
        return -1;

    memset(&req, 0, sizeof(req));
    req.cmh.type = CTRLMSG_TYPE_REGISTER;
    req.cmh.len = htons(sizeof(req));
    req.cmh.xid = ++hc->xid;
	req.srvid_prefix_bits = 
        (prefix_bits > SERVICE_ID_MAX_PREFIX_BITS) ?
        0 : prefix_bits;
    memcpy(&req.srvid, srvid, sizeof(*srvid));

    if (old_ip) {
        req.flags |= REG_FLAG_REREGISTER;
        memcpy(&req.addr, old_ip, sizeof(*old_ip));
    }
        
    LOG_DBG("prefix_bits=%u sizeof(req)=%zu %s\n",
            req.srvid_prefix_bits, 
            sizeof(req), 
            service_id_to_str(&req.srvid));
                
    return message_channel_send(hc->mc, &req.cmh, sizeof(req));
}

static int remote_service_unregister(struct hostctrl *hc, 
                                     const struct service_id *srvid,
                                     unsigned short prefix_bits)
{
    struct ctrlmsg_register req;

    if (!srvid)
        return -1;

    memset(&req, 0, sizeof(req));
    req.cmh.type = CTRLMSG_TYPE_UNREGISTER;
    req.cmh.len = htons(sizeof(req));
    req.cmh.xid = ++hc->xid;
	req.srvid_prefix_bits = 
        (prefix_bits > SERVICE_ID_MAX_PREFIX_BITS) ?
        0 : prefix_bits;
    memcpy(&req.srvid, srvid, sizeof(*srvid));
    //memcpy(&req.address, ipaddr, sizeof(*ipaddr));
        
    LOG_DBG("prefix_bits=%u sizeof(req)=%zu %s\n",
            req.srvid_prefix_bits, 
            sizeof(req), 
            service_id_to_str(&req.srvid));
                
    return message_channel_send(hc->mc, &req.cmh, sizeof(req));
}

static int remote_service_add_dummy(struct hostctrl *hc,
                                    enum service_rule_type type,
                                    const struct service_id *srvid,
                                    unsigned short prefix_bits,
                                    unsigned int priority,
                                    unsigned int weight,
                                    const struct in_addr *ipaddr)
{
    return 0;
}

static int remote_service_remove_dummy(struct hostctrl *hc,
                                       enum service_rule_type type,
                                       const struct service_id *srvid, 
                                       unsigned short prefix_bits,
                                       const struct in_addr *ipaddr)
{
    return 0;
}

int remote_ctrlmsg_recv(struct hostctrl *hc, struct ctrlmsg *cm,
                        struct sockaddr *from, socklen_t from_len)
{
    struct in_addr *fromip = NULL;
    int ret = 0;
     
    if (from) {
        if (from->sa_family == AF_INET)
            fromip = &((struct sockaddr_in *)from)->sin_addr;
        else if (from->sa_family == AF_SERVAL && 
                 from_len > sizeof(struct sockaddr_in)) {
            channel_addr_t *addr = (channel_addr_t *)from;
            
            if (addr->sv_in.in.sin_family == AF_INET) {
                fromip = &addr->sv_in.in.sin_addr;
            }
        }
    }
    
    switch (cm->type) {
    case CTRLMSG_TYPE_REGISTER: {
        struct ctrlmsg_register *cmr = (struct ctrlmsg_register *)cm;

        if (!fromip)
            break;
        
        ret = hc->cbs->service_registration(hc, &cmr->srvid, 
                                            cmr->srvid_flags, 
                                            cmr->srvid_prefix_bits, 
                                            fromip, 
                                            cmr->flags & REG_FLAG_REREGISTER ? 
                                            &cmr->addr : NULL);
        break;
    }
    case CTRLMSG_TYPE_UNREGISTER: {
        struct ctrlmsg_register *cmr = (struct ctrlmsg_register *)cm;

        if (!fromip)
            break;

        ret = hc->cbs->service_unregistration(hc, &cmr->srvid, 
                                              cmr->srvid_flags, 
                                              cmr->srvid_prefix_bits, 
                                              fromip);
        break;
    }
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

struct hostctrl_ops remote_ops = {
    .service_add = remote_service_add_dummy,
    .service_remove = remote_service_remove_dummy,
	.service_register = remote_service_register,
	.service_unregister = remote_service_unregister,
    .ctrlmsg_recv = remote_ctrlmsg_recv,
};
