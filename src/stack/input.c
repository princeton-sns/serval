/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/platform.h>
#include <scaffold/skbuff.h>
#include <scaffold/netdevice.h>
#include <scaffold_sock.h>
#include <scaffold/debug.h>
#include <input.h>

extern int scaffold_ipv4_rcv(struct sk_buff *skb);

int scaffold_input(struct sk_buff *skb)
{
	char srcstr[18], dststr[18];
	struct ethhdr *ethh = eth_hdr(skb);
	uint16_t prot = ntohs(ethh->h_proto);
        int ret;

	mac_ntop(ethh->h_source, srcstr, sizeof(srcstr));
	mac_ntop(ethh->h_dest, dststr, sizeof(dststr));
	
	LOG_DBG("%s [%s %s 0x%04x]\n", 
		skb->dev->name, srcstr, dststr, prot);
        
        /* Set head to network part of packet */
        skb_pull(skb, skb->dev->hard_header_len);
        
        /* Set network header offset */
        skb_reset_network_header(skb);
        
        memcpy(skb_hard_dst(skb), ethh->h_source, ETH_ALEN);

        switch (prot) {
        case ETH_P_IP:
                ret = scaffold_ipv4_rcv(skb);
                break;
        default:
                ret = INPUT_NO_PROT;                
        }

        return ret;
}
