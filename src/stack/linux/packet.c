/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/platform.h>
#include <scaffold/debug.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <input.h>

static int scaffold_packet_rcv(struct sk_buff *skb, struct net_device *dev,
			       struct packet_type *pt, struct net_device *orig_dev)
{        
        int ret;

	skb_set_mac_header(skb, 0);
	
        switch (skb->pkt_type) {
        case PACKET_HOST:
                break;
        case PACKET_OTHERHOST:
        case PACKET_BROADCAST:
        case PACKET_MULTICAST:
        case PACKET_OUTGOING:
        default:
                goto free_skb;
        }
        
	ret = scaffold_input(skb);
        
	switch (ret) {
        case INPUT_KEEP:
                break;
        case INPUT_OK:
        case INPUT_ERROR:
        default:
                if (IS_INPUT_ERROR(ret)) {
                        LOG_ERR("input error\n");
                }
                goto free_skb;
        }		
finish:
        return NET_RX_SUCCESS;
free_skb:        
        kfree_skb(skb);

	goto finish;
}

/* Scaffold packet type for Scaffold over Ethernet */
static struct packet_type scaffold_packet_type = {
        .type = __constant_htons(ETH_P_IP),
        .func = scaffold_packet_rcv,
};

int __init packet_init(void)
{
	dev_add_pack(&scaffold_packet_type);

	return 0;
}

void __exit packet_fini(void)
{
        dev_remove_pack(&scaffold_packet_type);
}
