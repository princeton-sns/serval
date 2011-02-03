/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/platform.h>
#include <serval/skbuff.h>
#include <serval/netdevice.h>
#include <serval/debug.h>
#include <serval_sock.h>
#include <netinet/serval.h>
#include <serval_srv.h>
#include <serval_ipv4.h>
#include <output.h>
#include <neighbor.h>
#if defined(OS_USER)
#include <netinet/ip.h>
#endif

extern int packet_xmit(struct sk_buff *skb);

int serval_output(struct sk_buff *skb)
{
	char srcstr[18], dststr[18];
	struct ethhdr *ethh;
        struct neighbor_entry *neigh;
	int err;

        if (!skb->dev) {
                err =  -ENODEV;
                goto drop;
        }
        
        neigh = neighbor_find((struct net_addr *)&ip_hdr(skb)->daddr);

        if (!neigh) {
                char buf[15];
                LOG_ERR("no matching neighbor for %s\n", 
                        inet_ntop(AF_INET, &ip_hdr(skb)->daddr,
                                  buf, 15));
                err = -EHOSTUNREACH;
                goto drop;
        }
        
	err = dev_hard_header(skb, skb->dev, ntohs(skb->protocol), 
			      neigh->dstaddr, NULL, skb->len);

        neighbor_entry_put(neigh);

	if (err < 0) {
		LOG_ERR("hard_header failed\n");
		goto drop;
	} else {
                /* dev_hard_header returns header length.
                   Reset to no error.
                */
                err = 0;
        }

        skb_reset_mac_header(skb);
	ethh = eth_hdr(skb);
	mac_ntop(ethh->h_source, srcstr, sizeof(srcstr));
	mac_ntop(ethh->h_dest, dststr, sizeof(dststr));

	LOG_DBG("%s [%s %s 0x%04x]\n", 
		skb->dev->name, srcstr, 
                dststr, ntohs(skb->protocol));
        /*
        {
                char dump[256];
                LOG_DBG("dump: %s\n", hexdump(skb->data, skb->len, dump, 256));
        }
        */
	/* packet_xmit consumes the packet no matter the outcome */
	if (dev_queue_xmit(skb) < 0) {
		LOG_ERR("packet_xmit failed\n");
	}
        
out:
        return err;
drop:
        FREE_SKB(skb);
        goto out;
}
