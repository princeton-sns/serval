/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/platform.h>
#include <scaffold/skbuff.h>
#include <scaffold/netdevice.h>
#include <scaffold/debug.h>
#include <scaffold_sock.h>
#include <output.h>

extern int packet_xmit(struct sk_buff *skb);

int scaffold_output(struct sk_buff *skb)
{
	char srcstr[18], dststr[18];
	unsigned char mac[ETH_ALEN] = { 0x0a, 0x00, 0x27, 0x00, 0x00, 0x00 };
	struct ethhdr *ethh;
	int err;

	err = dev_hard_header(skb, skb->dev, ntohs(skb->protocol), 
			      mac, NULL, skb->len);
	if (err < 0) {
		LOG_ERR("hard_header failed\n");
		return err;
	}

        skb_reset_mac_header(skb);
	ethh = eth_hdr(skb);
	mac_ntop(ethh->h_source, srcstr, sizeof(srcstr));
	mac_ntop(ethh->h_dest, dststr, sizeof(dststr));

	LOG_DBG("sending packet if=%d [%s %s 0x%04x]\n", 
		skb->dev->ifindex, srcstr, dststr, ntohs(skb->protocol));
	       
	/* packet_xmit consumes the packet no matter the outcome */
	if (dev_queue_xmit(skb) < 0) {
		LOG_ERR("packet_xmit failed\n");
	}

        return 0;
}
