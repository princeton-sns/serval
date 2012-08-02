/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- 
 *
 * Receive/send Serval packets on a RAW IP socket.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#include <serval/netdevice.h>
#include <serval/skbuff.h>
#include <serval/debug.h>
#include <netinet/serval.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/socket.h>
#if !defined(OS_ANDROID)
#include <net/ethernet.h> 
#endif
#include "packet.h"

extern int serval_ipv4_rcv(struct sk_buff *skb);

#define RCVLEN (1500 + SKB_HEADROOM_RESERVE) /* Should be more than
					      * enough for normal
					      * MTUs */
#define get_priv(dev) ((struct packet_raw_priv *)dev_get_priv(dev))

static int packet_raw_init(struct net_device *dev)
{
        struct sockaddr_in addr;
	int ret, val = 1;

	dev->fd = socket(AF_INET, SOCK_RAW, IPPROTO_SERVAL);

        if (dev->fd == -1) {
                LOG_ERR("packet socket: %s\n", strerror(errno));
                return -1;
        }

        /* Bind the raw IP socket to the device */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        /* Binding to the interface IP will stop us from receiving
           broadcast packets */
	/* dev_get_ipv4_addr(dev, IFADDR_LOCAL, &addr.sin_addr); */
        addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = 0;
	       
        LOG_DBG("binding to %s\n",
                inet_ntoa(addr.sin_addr));

        ret = bind(dev->fd, (struct sockaddr *)&addr, sizeof(addr));

        if (ret == -1) {
                LOG_ERR("bind failure: %s\n",
                        strerror(errno));
                close(dev->fd);
		dev->fd = -1;
        }

	ret = setsockopt(dev->fd, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val));

	if (ret == -1) {
                LOG_ERR("setsockopt IP_HDRINCL failure: %s\n",
                        strerror(errno));
                close(dev->fd);
		dev->fd = -1;
	}

	ret = setsockopt(dev->fd, SOL_SOCKET, SO_BROADCAST, &val, sizeof(val));

	if (ret == -1) {
                LOG_ERR("setsockopt SO_BROADCAST failure: %s\n",
                        strerror(errno));
                close(dev->fd);
		dev->fd = -1;
	}
#if defined(OS_LINUX)
	ret = setsockopt(dev->fd, SOL_SOCKET, SO_BINDTODEVICE, 
                         dev->name, strlen(dev->name));

	if (ret == -1) {
                LOG_ERR("setsockopt SO_BINDTODEVICE failure: %s\n",
                        strerror(errno));
                close(dev->fd);
		dev->fd = -1;
	}
#elif defined(OS_BSD)
        /* TODO: add the BSD equivalent of SO_BINDTODEVICE */
#endif

	return ret;
}

static void packet_raw_destroy(struct net_device *dev)
{
	if (dev->fd != -1) {
		close(dev->fd);
		dev->fd = -1;
	}
}

static int packet_raw_recv(struct net_device *dev)
{
	struct sk_buff *skb = NULL;
	struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);
	int ret;

	skb = alloc_skb(RCVLEN, 0);
        
	if (!skb) {
		LOG_ERR("could not allocate skb\n");
		return -1;
	}

	/* skb_reserve(skb, SKB_HEADROOM_RESERVE); */
        
	ret = recvfrom(dev->fd, skb->data, RCVLEN, 0, 
                       (struct sockaddr *)&addr, &addrlen);
	
	if (ret == -1) {
		LOG_ERR("recv: %s\n", 
			strerror(errno));
		__kfree_skb(skb);
		return -1;
	} else if (ret == 0) {
		/* Should not happen */
                LOG_ERR("recv return 0\n");
		__kfree_skb(skb);
		return -1;
	}
        /*
          LOG_DBG("Received %d bytes IP packet on device %s\n", 
                ret, dev->name);
        */        
        __net_timestamp(skb);
        skb->pkt_type = PACKET_OTHERHOST;
        skb_put(skb, ret);
	skb->dev = dev;
        /* Set network header offset */
	skb_reset_network_header(skb);

	/* Try to figure out what packet type this is by comparing the
	 * incoming IP destination against the device's IP
	 * configuration */
        if (memcmp(&ip_hdr(skb)->daddr, 
                   &dev->ipv4.addr, 
                   sizeof(dev->ipv4.addr)) == 0) {
                skb->pkt_type = PACKET_HOST;
        } else if (memcmp(&ip_hdr(skb)->daddr, 
                          &dev->ipv4.broadcast, 
                          sizeof(dev->ipv4.broadcast)) == 0 || 
                   ip_hdr(skb)->daddr == 0xffffffff) {
                skb->pkt_type = PACKET_BROADCAST;
        }
                
        /* skb->pkt_type = */
	skb->protocol = IPPROTO_IP;

        skb->csum = 0;
        skb->ip_summed = CHECKSUM_NONE;

	/* Packet should be freed by upper layers */
	return serval_ipv4_rcv(skb);
}

static int packet_raw_xmit(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct sockaddr_in addr;
	int err;

	memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
	memcpy(&addr.sin_addr, &iph->daddr, sizeof(iph->daddr));

#if defined(ENABLE_DEBUG)
        {
                char buf[18];
                LOG_DBG("%s XMIT len=%u dest=%s\n",
                        skb->dev->name,
                        skb->len,
                        inet_ntop(AF_INET, &iph->daddr,
                                  buf, 18));
        }
#endif
	err = sendto(skb->dev->fd, skb->data, skb->len, 0, 
		     (struct sockaddr *)&addr, sizeof(addr));

	if (err == -1) {
		LOG_ERR("send error: %s\n", 
			strerror(errno));
                err = NET_XMIT_DROP;
	} else {
                err = NET_XMIT_SUCCESS;
        }

	kfree_skb(skb);

	return err;
}

static struct packet_ops pack_ops = {
	.init = packet_raw_init,
	.destroy = packet_raw_destroy,
	.recv = packet_raw_recv,
	.xmit = packet_raw_xmit
};

static void dev_setup(struct net_device *dev)
{
	dev->pack_ops = &pack_ops;
	ether_setup(dev);
}

int packet_init(void)
{
        int ret;

        ret = netdev_init();

        if (ret < 0) {
                return ret;
        }

        ret = netdev_populate_table(0, dev_setup);

        if (ret < 0)
                netdev_fini();

        return ret;
}

void packet_fini(void)
{
        netdev_fini();
}
