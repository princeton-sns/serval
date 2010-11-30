/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/netdevice.h>
#include <scaffold/debug.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#if defined(OS_BSD)
#include <net/if_dl.h>
#include <ifaddrs.h>
#endif
#if !defined(OS_ANDROID)
#include <net/ethernet.h>
#endif

void ether_setup(struct net_device *dev)
{	
	dev->hard_header_len = ETH_HLEN;
	dev->addr_len = ETH_ALEN;
}

#if defined(OS_BSD)
static int get_macaddr(const char *devname, unsigned char mac[6])
{
        int ret = 0;
        struct ifaddrs *ifa = NULL, *tmp;
        
        ret = getifaddrs(&ifa);

        if (ret == -1) {
                LOG_ERR("could not get interface list\n");
                return ret;
        }

        tmp = ifa;

        while (ifa) {
                if (strcmp(ifa->ifa_name, devname) == 0) {
#if defined(OS_BSD)
                        struct sockaddr_dl *ifaddr = 
                                (struct sockaddr_dl *)ifa->ifa_addr;

                        if (ifaddr->sdl_family != AF_LINK) {
                                ifa = ifa->ifa_next;
                                continue;
                        }
                        
                        memcpy(mac, LLADDR(ifaddr), ETH_ALEN);
#else
                        memcpy(mac, ifa->ifa_addr->sa_data, ETH_ALEN);
#endif
                        ret = 1;
                        break;
                }
                
                ifa = ifa->ifa_next;
        }
        
        freeifaddrs(tmp);
                
        return ret;
}

#endif

struct net_device *alloc_netdev(int sizeof_priv, const char *name,
				void (*setup)(struct net_device *))
{
	struct net_device *dev;
	struct ifreq ifr;
        int sock;

	dev = (struct net_device *)malloc(sizeof(struct net_device));
	
	if (!dev)
		return NULL;
	
	memset(dev, 0, sizeof(struct net_device));
	strcpy(dev->name, name);
        dev->ifindex = if_nametoindex(name);
	atomic_set(&dev->refcnt, 1);
	dev->dev_addr = dev->perm_addr;

        memset(&ifr, 0, sizeof(struct ifreq));
        strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);

#if defined(OS_BSD)
#define SIOCGIFHWADDR SIOCGIFADDR
#endif
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        
        if (sock != -1) {
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
                        LOG_ERR("could not get hw address of interface '%s'\n",
                                name);
                } else {
#if defined(OS_BSD)
                        if (get_macaddr(name, dev->perm_addr) == 1) {
                                LOG_DBG("mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
                                        dev->perm_addr[0],
                                        dev->perm_addr[1],
                                        dev->perm_addr[2],
                                        dev->perm_addr[3],
                                        dev->perm_addr[4],
                                        dev->perm_addr[5]);
                        } else {
                                LOG_ERR("No hw address of interface %s\n", name);
                        }
#elif defined(OS_LINUX)
                        memcpy(dev->perm_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
#endif
                }
                close(sock);
        } else {
                LOG_ERR("could not open ioctl socket\n", strerror(errno));
        }
       
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
