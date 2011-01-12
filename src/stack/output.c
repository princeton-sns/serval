/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/platform.h>
#include <scaffold/skbuff.h>
#include <scaffold/netdevice.h>
#include <scaffold/debug.h>
#include <scaffold_sock.h>
#include <netinet/scaffold.h>
#include <scaffold_srv.h>
#include <scaffold_ipv4.h>
#include <output.h>
#include <neighbor.h>
#if defined(OS_USER)
#include <netinet/ip.h>
#endif

extern int packet_xmit(struct sk_buff *skb);

const char *skb_dump(const void *data, int datalen, char *buf, int buflen)
{
        int i = 0, len = 0;
        const unsigned char *h = (const unsigned char *)data;
        
        while (i < datalen) {
                unsigned char c = (i + 1 < datalen) ? h[i+1] : 0;
                len += snprintf(buf + len, buflen - len, 
                                "%02x%02x ", h[i], c);
                i += 2;
        }
        return buf;
}

int scaffold_output(struct sk_buff *skb)
{
	char srcstr[18], dststr[18];
	struct ethhdr *ethh;
        struct neighbor_entry *neigh;
	int err;

        if (!skb->dev) {
                err =  -ENODEV;
                goto drop;
        }
        
        neigh = neighbor_find((struct flow_id *)&ip_hdr(skb)->daddr);

        if (!neigh) {
                char buf[15];
                LOG_ERR("No matching neighbor for %s\n", 
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
        {
                char dump[256];
                LOG_DBG("dump: %s\n", skb_dump(skb->data, skb->len, dump, 256));
        }
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
