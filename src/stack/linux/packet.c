/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/platform.h>
#include <scaffold/debug.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <input.h>

#define USE_NETFILTER 1

#if defined(USE_NETFILTER)
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static unsigned int scaffold_packet_rcv(unsigned int hooknum,
                                        struct sk_buff *skb,
                                        const struct net_device *in,
                                        const struct net_device *out,
                                        int (*okfn)(struct sk_buff *))
{
        int ret;

        switch (skb->pkt_type) {
        case PACKET_HOST:
                break;
        case PACKET_OTHERHOST:
        case PACKET_OUTGOING:
        case PACKET_BROADCAST:
        case PACKET_MULTICAST:
        default:
                goto accept;
        }
        
	ret = scaffold_input(skb);
        
	switch (ret) {
        case INPUT_KEEP:
                goto keep;
        case INPUT_DROP:
        case INPUT_OK:
                goto drop;
        case INPUT_DELIVER:
                break;
        case INPUT_ERROR:
        default:
                if (IS_INPUT_ERROR(ret)) {
                        LOG_ERR("input error\n");
                }
        }
accept:
        LOG_DBG("Returning NF_ACCEPT\n");
        return NF_ACCEPT;
drop:   
        LOG_DBG("Returning NF_DROP\n");
        return NF_DROP;
keep:
        LOG_DBG("Returning NF_STOLEN\n");
	return NF_STOLEN;
}

static struct nf_hook_ops ip_hook = { 
        .hook = scaffold_packet_rcv, 
        .hooknum = NF_INET_PRE_ROUTING,
        .pf = PF_INET,
        .priority = NF_IP_PRI_FIRST,
};

#else
#include <linux/netdevice.h>

static int scaffold_packet_rcv(struct sk_buff *skb, struct net_device *dev,
			       struct packet_type *pt, struct net_device *orig_dev)
{        
        int ret;

        switch (skb->pkt_type) {
        case PACKET_HOST:
                break;
        case PACKET_OTHERHOST:
                goto drop;
        case PACKET_OUTGOING:
                goto finish;
        case PACKET_BROADCAST:
        case PACKET_MULTICAST:
        default:
                goto drop;
        }
        
	ret = scaffold_input(skb);
        
	switch (ret) {
        case INPUT_KEEP:
                goto keep;
        case INPUT_DROP:
                goto drop;
        case INPUT_OK:
                goto drop;
        case INPUT_DELIVER:
                break;
        case INPUT_ERROR:
        default:
                if (IS_INPUT_ERROR(ret)) {
                        LOG_ERR("input error\n");
                }
                goto drop;
        }		
finish:
        /* Returning NET_RX_SUCCESS will deliver the packet to other
         * modules, e.g., normal IP */
        LOG_DBG("Returning NET_RX_SUCCESS\n");
        return NET_RX_SUCCESS;
drop:   
        LOG_DBG("freeing skb\n");
        kfree_skb(skb);
keep:
        LOG_DBG("Returning NET_RX_DROP\n");
	return NET_RX_DROP;
}

/* Scaffold packet type for Scaffold over Ethernet */
static struct packet_type scaffold_packet_type = {
        .type = __constant_htons(ETH_P_IP),
        .func = scaffold_packet_rcv,
};

#endif /* USE_NETFILTER */

int __init packet_init(void)
{
#if defined(USE_NETFILTER)
        if (nf_register_hook(&ip_hook) < 0)
                return -1;
#else
	dev_add_pack(&scaffold_packet_type);
#endif
	return 0;
}

void __exit packet_fini(void)
{
#if defined(USE_NETFILTER)
        nf_unregister_hook(&ip_hook);
#else
        dev_remove_pack(&scaffold_packet_type);
#endif
}
