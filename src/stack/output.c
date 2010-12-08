/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/platform.h>
#include <scaffold/skbuff.h>
#include <scaffold/netdevice.h>
#include <scaffold/debug.h>
#include <scaffold_sock.h>
#include <netinet/scaffold.h>
#include <output.h>

extern int packet_xmit(struct sk_buff *skb);

#define SERVICE_ROUTER_ID 666

int scaffold_output(struct sk_buff *skb)
{
	char srcstr[18], dststr[18];
	unsigned char mac[ETH_ALEN] = { 0x0a, 0x00, 0x27, 0x00, 0x00, 0x00 };
        unsigned char *dst = mac;
	struct ethhdr *ethh;
        struct service_id *srvid = skb_dst_service_id(skb);
	int err;

        if (!skb->dev)
                return -ENODEV;

        /*
          FIXME:

          The way the layer 2 address is figured out is a hack.

          We should use layer 3 addresses here to map to layer 2
          addresses. Some type of neighbor cache is probably needed.
          
          If we should run on top of unmodified IP, we would probably
          send at layer 3 as well, not caring about layer 2.
        */
        if (srvid->s_sid16 == htons(SERVICE_ROUTER_ID)) {
                dst = skb->dev->broadcast;
        }

	err = dev_hard_header(skb, skb->dev, ntohs(skb->protocol), 
			      dst, NULL, skb->len);
	if (err < 0) {
		LOG_ERR("hard_header failed\n");
		return err;
	}

        skb_reset_mac_header(skb);
	ethh = eth_hdr(skb);
	mac_ntop(ethh->h_source, srcstr, sizeof(srcstr));
	mac_ntop(ethh->h_dest, dststr, sizeof(dststr));

	LOG_DBG("%s [%s %s 0x%04x]\n", 
		skb->dev->name, srcstr, 
                dststr, ntohs(skb->protocol));
	       
	/* packet_xmit consumes the packet no matter the outcome */
	if (dev_queue_xmit(skb) < 0) {
		LOG_ERR("packet_xmit failed\n");
	}

        return 0;
}
