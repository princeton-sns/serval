/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/netdevice.h>
#include <scaffold/debug.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <string.h>

void ether_setup(struct net_device *dev)
{	
	dev->hard_header_len = ETH_HLEN;
	dev->addr_len = ETH_ALEN;
}

struct net_device *alloc_netdev(int sizeof_priv, const char *name,
				void (*setup)(struct net_device *))
{
	struct net_device *dev;
	
	dev = (struct net_device *)malloc(sizeof(struct net_device));
	
	if (!dev)
		return NULL;
	
	memset(dev, 0, sizeof(struct net_device));
	strcpy(dev->name, name);
	atomic_set(&dev->refcnt, 1);
	dev->dev_addr = dev->perm_addr;

	setup(dev);

	return dev;
}

void __free_netdev(struct net_device *dev)
{
	free(dev);
}

void free_netdev(struct net_device *dev)
{
	if (atomic_dec_and_test(&dev->refcnt))
		__free_netdev(dev);
}
