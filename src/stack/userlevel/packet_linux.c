/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/netdevice.h>
#include <scaffold/skbuff.h>
#include <scaffold/debug.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#if !defined(OS_ANDROID)
#include <net/ethernet.h> 
#endif
#include "packet.h"
#include <input.h>

#define RCVLEN 2000 /* Should be more than enough for normal MTUs */
#define get_priv(dev) ((struct packet_linux_priv *)dev_get_priv(dev))

static int packet_linux_init(struct net_device *dev)
{
        struct sockaddr_ll lladdr;
	int ret;

	dev->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));

        if (dev->fd == -1) {
                LOG_ERR("packet socket: %s\n", strerror(errno));
                return -1;
        }

        /* Bind the packet socket to the device */
        memset(&lladdr, 0, sizeof(lladdr));
        lladdr.sll_family = AF_PACKET;
        lladdr.sll_ifindex = dev->ifindex;

        ret = bind(dev->fd, (struct sockaddr *)&lladdr, sizeof(lladdr));

        if (ret == -1) {
                LOG_ERR("bind failure: %s\n",
                        strerror(errno));
                close(dev->fd);
		dev->fd = -1;
        }
	return ret;
}

static void packet_linux_destroy(struct net_device *dev)
{
	if (dev->fd != -1) {
		close(dev->fd);
		dev->fd = -1;
	}
}

static int packet_linux_recv(struct net_device *dev)
{
	struct sk_buff *skb = NULL;
	struct sockaddr_ll lladdr;
	socklen_t addrlen = sizeof(lladdr);
	int ret;

	skb = alloc_skb(RCVLEN);
        
	if (!skb) {
		LOG_ERR("could not allocate skb\n");
		return -1;
	}
        
	ret = recvfrom(dev->fd, skb->data, RCVLEN, 0,
		       (struct sockaddr *)&lladdr, 
		       &addrlen);
	
	if (ret == -1) {
		LOG_ERR("recvfrom: %s\n", 
			strerror(errno));
		free_skb(skb);
		return -1;
	} else if (ret == 0) {
		/* Should not happen */
		free_skb(skb);
		return -1;
	}
        
	switch (lladdr.sll_pkttype) {
	case PACKET_HOST:
	case PACKET_BROADCAST:
	case PACKET_MULTICAST:
		break;
	case PACKET_OUTGOING:
	case PACKET_OTHERHOST:
	case PACKET_LOOPBACK:
	default:
		free_skb(skb);
		return -1;              
	}
        
	skb->dev = dev;
	skb_reset_mac_header(skb);
	skb->pkt_type = lladdr.sll_pkttype;
	skb->protocol = lladdr.sll_protocol;

	ret = scaffold_input(skb);
	
	switch (ret) {
	case INPUT_OK:
                break;
	case INPUT_ERROR:
                /* Packet should be freed by upper layers */
		if (IS_INPUT_ERROR(ret)) {
			LOG_ERR("input error\n");
		}
		break;
        case INPUT_NO_PROT:
        case INPUT_DROP:
        case INPUT_DELIVER:
        default:
                free_skb(skb);
	}

	return 0;
}

static int packet_linux_xmit(struct sk_buff *skb)
{
	struct sockaddr_ll lladdr;
	int err;

	if (!skb->dev) {
		free_skb(skb);
		return -1;
	}
	memset(&lladdr, 0, sizeof(lladdr));
	lladdr.sll_family = AF_PACKET;
	lladdr.sll_ifindex = skb->dev->ifindex;
	lladdr.sll_protocol = skb->protocol;
	lladdr.sll_pkttype = PACKET_OUTGOING;
        
	err = sendto(skb->dev->fd, skb->data, 
		     skb->len, 0, 
		     (struct sockaddr *)&lladdr, 
		     sizeof(lladdr));
	
	if (err == -1) {
		LOG_ERR("sendto error: %s\n", 
			strerror(errno));
                err = NET_XMIT_DROP;
	} else {
                err = NET_XMIT_SUCCESS;
        }

	free_skb(skb);

	return err;
}

static struct packet_ops pack_ops = {
	.init = packet_linux_init,
	.destroy = packet_linux_destroy,
	.recv = packet_linux_recv,
	.xmit = packet_linux_xmit
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
