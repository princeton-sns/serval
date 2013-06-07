/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <libservalctrl/hostctrl.h>
#include <serval/platform.h>
#include <serval/ctrlmsg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/serval.h>
#if defined(OS_UNIX)
#include <sys/socket.h>
#include <sys/un.h>
#endif
#include "hostctrl_ops.h"

extern struct hostctrl_ops local_ops;
extern struct hostctrl_ops remote_ops;

static struct hostctrl_ops *hops[] = {
#if defined(OS_LINUX)
	[MSG_CHANNEL_NETLINK] = &local_ops,
#endif
#if defined(OS_UNIX)
	[MSG_CHANNEL_UNIX] = &local_ops,
#endif
	[MSG_CHANNEL_UDP] = &remote_ops,
};

static int hostctrl_recv(struct message_channel_callback *mcb, 
                         struct message *m)
{
    struct hostctrl *hc = (struct hostctrl *)mcb->target;
	struct ctrlmsg *cm = (struct ctrlmsg *)m->data;

    if (!hc->ops)
        return 0;

	return hc->ops->ctrlmsg_recv(hc, cm, &m->from.sa, m->from_len);
}

static int on_start_message_channel(struct message_channel_callback *mcb)
{
    struct hostctrl *hc = (struct hostctrl *)mcb->target;

    if (hc && hc->cbs && hc->cbs->start)
        return hc->cbs->start(hc);
    return 0;
}

static void on_stop_message_channel(struct message_channel_callback *mcb)
{
    struct hostctrl *hc = (struct hostctrl *)mcb->target;
        
    if (hc && hc->cbs && hc->cbs->stop)
        hc->cbs->stop(hc);       
}

static struct hostctrl *hostctrl_create(struct message_channel *mc, 
                                        const struct hostctrl_callback *cbs,
                                        void *context)
{
	struct hostctrl *hc;

	hc = malloc(sizeof(*hc));

	if (!hc)
		return NULL;

	memset(hc, 0, sizeof(*hc));
	
	hc->mccb.target = hc;
	hc->mccb.recv = hostctrl_recv;
    hc->mccb.start = on_start_message_channel;
    hc->mccb.stop = on_stop_message_channel;
	hc->mc = mc;
    hc->context = context;
	hc->ops = hops[message_channel_get_type(mc)];
	hc->cbs = cbs;
	message_channel_register_callback(mc, &hc->mccb);

	return hc;
}

struct hostctrl *hostctrl_local_create(const struct hostctrl_callback *cbs,
                                       void *context, 
                                       unsigned short flags)
{
	struct message_channel *mc = NULL;
    struct hostctrl *hc;
#if defined(OS_LINUX)
	struct sockaddr_nl local, peer;
        
	memset(&peer, 0, sizeof(peer));
    peer.nl_family = AF_NETLINK;
	peer.nl_pid = 0; /* kernel */

	/* the multicast group */
	peer.nl_groups = 0;
    
	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_pid = 0; /* Auto assign ID */
	/* the multicast group */
	local.nl_groups = 1;
	
	mc = message_channel_get_generic(MSG_CHANNEL_NETLINK, SOCK_RAW, 
                                     NETLINK_SERVAL, 
                                     (struct sockaddr *)&local, 
                                     sizeof(local), 
                                     (struct sockaddr *)&peer, 
                                     sizeof(peer), 0);
        
#endif

	if (!mc) {
#if defined(OS_UNIX) && defined(ENABLE_USERMODE)
        struct sockaddr_un local, peer;

        memset(&local, 0, sizeof(local));
        memset(&peer, 0, sizeof(peer));
                
        local.sun_family = PF_UNIX;
        snprintf(local.sun_path, sizeof(local.sun_path), 
                 "/tmp/serval-client-%u-ctrl.sock", 
                 getpid());
                
        peer.sun_family = PF_UNIX;
        strcpy(peer.sun_path, SERVAL_STACK_CTRL_PATH);
                
        mc = message_channel_get_generic(MSG_CHANNEL_UNIX, SOCK_DGRAM, 
                                         0, (struct sockaddr *)&local, 
                                         sizeof(local), 
                                         (struct sockaddr *)&peer, 
                                         sizeof(peer), 0);

#endif
        if (!mc) {
            LOG_ERR("Could not create local host control interface\n");
            return NULL;
        }
	}
	
	hc = hostctrl_create(mc, cbs, context);

    if (!hc)
        message_channel_put(mc);
    else if (flags & HCF_START) {
        if (hostctrl_start(hc) == -1) {
            hostctrl_free(hc);
            return NULL;
        }
    }

    return hc;
}

struct hostctrl *
hostctrl_remote_create_specific(const struct hostctrl_callback *cbs,
                                void *context, 
                                struct sockaddr *local, socklen_t local_len ,
                                struct sockaddr *peer, socklen_t peer_len, 
                                unsigned short flags)
{
	struct message_channel *mc = NULL;
    struct hostctrl *hc;

 	mc = message_channel_get_generic(MSG_CHANNEL_UDP, SOCK_DGRAM, 0, 
                                     local, local_len,
                                     peer, peer_len, 0);
        
	if (!mc) {
		LOG_DBG("Could not create remote host control interface\n");
		return NULL;
	}
        
    hc = hostctrl_create(mc, cbs, context);

    if (!hc)
        message_channel_put(mc);
    else if (flags & HCF_START) {
        if (hostctrl_start(hc) == -1) {
            hostctrl_free(hc);
            return NULL;
        }
    }
                
    return hc;
}

struct hostctrl *hostctrl_remote_create(const struct hostctrl_callback *cbs,
                                        void *context, 
                                        unsigned short flags)
{
    struct sockaddr_sv raddr, laddr;

    memset(&raddr, 0, sizeof(raddr));
    memset(&laddr, 0, sizeof(laddr));
        
    raddr.sv_family = AF_SERVAL;
    raddr.sv_srvid.srv_un.un_id32[0] = 
        flags & HCF_ROUTER ? htonl(333333) : htonl(444444);

    laddr.sv_family = AF_SERVAL;
    laddr.sv_srvid.srv_un.un_id32[0] =
        flags & HCF_ROUTER ? htonl(444444) : htonl(333333);
	
	return hostctrl_remote_create_specific(cbs, context,
                                           (struct sockaddr *)&laddr, 
                                           sizeof(laddr),
                                           (struct sockaddr *)&raddr, 
                                           sizeof(raddr),
                                           flags);
}

int hostctrl_start(struct hostctrl *hc)
{
    return message_channel_start(hc->mc);
}

void hostctrl_free(struct hostctrl *hc)
{
    message_channel_stop(hc->mc);
	message_channel_unregister_callback(hc->mc, &hc->mccb);
	message_channel_put(hc->mc);
	free(hc);
}

unsigned int hostctrl_get_xid(struct hostctrl *hc)
{
    return hc->xid;
}

int hostctrl_interface_migrate(struct hostctrl *hc, 
                               const char *from, const char *to)
{
    return hc->ops->interface_migrate(hc, from, to);
}

int hostctrl_flow_migrate(struct hostctrl *hc, struct flow_id *flow,
                          const char *to_iface)
{
    return hc->ops->flow_migrate(hc, flow, to_iface);
}

int hostctrl_service_migrate(struct hostctrl *hc, struct service_id *srvid,
                             const char *to_iface)
{
    return hc->ops->service_migrate(hc, srvid, to_iface);
}

int hostctrl_flow_stats_query(struct hostctrl *hc, struct flow_id *flowids,
                              int flows)
{
    return hc->ops->flow_stats_query(hc, flowids, flows);
}

int hostctrl_service_register(struct hostctrl *hc, 
                              const struct service_id *srvid, 
                              unsigned short prefix_bits,
                              const struct in_addr *old_ip)
{
    return hc->ops->service_register(hc, srvid, prefix_bits, old_ip);
}

int hostctrl_service_unregister(struct hostctrl *hc,
                                const struct service_id *srvid, 
                                unsigned short prefix_bits)
{
    struct service_id default_service;

    memset(&default_service, 0, sizeof(default_service));

    if (srvid == NULL)
        srvid = &default_service;

    return hc->ops->service_unregister(hc, srvid, prefix_bits);
}

int hostctrl_service_add(struct hostctrl *hc,
                         enum service_rule_type type,
                         const struct service_id *srvid, 
                         unsigned short prefix_bits,
                         unsigned int priority,
                         unsigned int weight,
                         const struct in_addr *ipaddr)
{
    struct service_id default_service;

    memset(&default_service, 0, sizeof(default_service));

    if (srvid == NULL)
        srvid = &default_service;

    return hc->ops->service_add(hc, type, srvid, prefix_bits, 
                                priority, weight, ipaddr);
}

int hostctrl_service_remove(struct hostctrl *hc,
                            enum service_rule_type type,
                            const struct service_id *srvid, 
                            unsigned short prefix_bits,
                            const struct in_addr *ipaddr)
{
    return hc->ops->service_remove(hc, type, srvid, prefix_bits, ipaddr);
}

int hostctrl_service_get(struct hostctrl *hc, 
                         const struct service_id *srvid, 
                         unsigned short prefix_bits,
                         const struct in_addr *ipaddr)
{
    struct service_id default_service;

    memset(&default_service, 0, sizeof(default_service));

    if (srvid == NULL)
        srvid = &default_service;

    return hc->ops->service_get(hc, srvid, prefix_bits, ipaddr);
}

int hostctrl_service_modify(struct hostctrl *hc,
                            enum service_rule_type type,
                            const struct service_id *srvid, 
                            unsigned short prefix_bits,
                            unsigned int priority,
                            unsigned int weight,
                            const struct in_addr *old_ip,
                            const struct in_addr *new_ip)
{
    return hc->ops->service_modify(hc, type, srvid, prefix_bits,
                                   priority, weight,
                                   old_ip, new_ip);
}

int hostctrl_services_add(struct hostctrl *hc,
                          const struct service_info *si,
                          unsigned int num_si)
{
    LOG_ERR("Not implemented yet!\n");
    return 0;
}

int hostctrl_services_remove(struct hostctrl *hc,
                             const struct service_info *si,
                             unsigned int num_si)
{
    LOG_ERR("Not implemented yet!\n");
    return 0;
}

int hostctrl_service_query(struct hostctrl *hc,
                           struct service_id *srvid,
                           unsigned short flags,
                           unsigned short prefix,
                           struct service_info_stat **si)
{
    LOG_ERR("Not implemented yet!\n");
    return 0;
}

int hostctrl_set_capabilities(struct hostctrl *hc,
                              uint32_t capabilities)
{
    LOG_ERR("Not implemented yet!\n");
    return 0;
}

int hostctrl_get_local_addr(struct hostctrl *hc,
                            struct sockaddr *addr, 
                            socklen_t *addrlen)
{
    return message_channel_get_local(hc->mc, addr, addrlen);
}

int hostctrl_get_peer_addr(struct hostctrl *hc,
                           struct sockaddr *addr, 
                           socklen_t *addrlen)
{
    return message_channel_get_peer(hc->mc, addr, addrlen);
}

int hostctrl_set_delay_verdict(struct hostctrl *hc,
                               unsigned int pkt_id,
                               enum delay_verdict verdict)
{
    if (hc && hc->ops->service_delay_verdict)
        return hc->ops->service_delay_verdict(hc, pkt_id, verdict);
    return -1;
}
