/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/netdevice.h>
#include <scaffold/debug.h>
#include <scaffold/list.h>
#include <scaffold/hash.h>
#include <scaffold/net.h>
#include <scaffold/skbuff.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <poll.h>
#include <string.h>
#if defined(OS_BSD)
#include <net/if_dl.h>
#endif
#if !defined(OS_ANDROID)
#include <net/ethernet.h>
#endif
#include "packet.h"
#include <input.h>
#include <service.h>

#define NETDEV_HASHBITS    8
#define NETDEV_HASHENTRIES (1 << NETDEV_HASHBITS)

DEFINE_RWLOCK(dev_base_lock);

struct net init_net = { 1 };

struct list_head dev_base_head;
struct hlist_head *dev_name_head;
struct hlist_head *dev_index_head;

static void *dev_thread(void *arg);

static inline struct hlist_head *dev_name_hash(struct net *net, 
                                               const char *name)
{
	unsigned hash = full_name_hash(name, 
                                       (strlen(name) > IFNAMSIZ) ? 
                                       IFNAMSIZ : strlen(name));
	return &dev_name_head[hash_32(hash, NETDEV_HASHBITS)];
}

static inline struct hlist_head *dev_index_hash(struct net *net, int ifindex)
{
	return &dev_index_head[ifindex & (NETDEV_HASHENTRIES - 1)];
}

static struct hlist_head *netdev_create_hash(void)
{
	int i;
	struct hlist_head *hash;

	hash = malloc(sizeof(*hash) * NETDEV_HASHENTRIES);

	if (hash != NULL)
		for (i = 0; i < NETDEV_HASHENTRIES; i++)
			INIT_HLIST_HEAD(&hash[i]);

	return hash;
}

void ether_setup(struct net_device *dev)
{	
	dev->hard_header_len = ETH_HLEN;
	dev->addr_len = ETH_ALEN;
	memset(dev->broadcast, 0xFF, ETH_ALEN);
}

static void netdev_init_one_queue(struct net_device *dev,
				  struct netdev_queue *queue,
				  void *_unused)
{
        memset(queue, 0, sizeof(*queue));
	queue->dev = dev;
        skb_queue_head_init(&queue->q);
}

struct net_device *alloc_netdev(int sizeof_priv, const char *name,
				void (*setup)(struct net_device *))
{
	struct net_device *dev;

	dev = (struct net_device *)malloc(sizeof(struct net_device) + 
                                          sizeof_priv);
	
	if (!dev)
		return NULL;
	
	memset(dev, 0, sizeof(struct net_device) + sizeof_priv);

        if (pipe(dev->pipefd) == -1) {
                LOG_ERR("pipe failure: %s\n", strerror(errno));
                free(dev);
                dev->pipefd[0] = -1;
                dev->pipefd[1] = -1;
                return NULL;
        }
	strcpy(dev->name, name);
        dev->ifindex = if_nametoindex(name);
	atomic_set(&dev->refcnt, 1);
	dev->dev_addr = dev->perm_addr;
        dev->tx_queue_len = 1000;
        
        netdev_init_one_queue(dev, &dev->tx_queue, NULL);

        setup(dev);

        /* Call the packet handlers init function if it exists */
        if (dev->pack_ops && dev->pack_ops->init) {
                if (dev->pack_ops->init(dev) == -1) {
                        LOG_ERR("packet ops init failed for device %s\n",
                                name);
                        free_netdev(dev);
                        dev = NULL;
                }
        }

	return dev;
}

void __free_netdev(struct net_device *dev)
{
        if (dev->pipefd[0] != -1) {
                close(dev->pipefd[0]);
                dev->pipefd[0] = -1;
        }
        if (dev->pipefd[1] != -1) {
                close(dev->pipefd[1]);
                dev->pipefd[1] = -1;
        }
	free(dev);
}

void free_netdev(struct net_device *dev)
{
	if (atomic_dec_and_test(&dev->refcnt))
		__free_netdev(dev);
}


/**
 *	__dev_get_by_name	- find a device by its name
 *	@net: the applicable net namespace
 *	@name: name to find
 *
 *	Find an interface by name. Must be called under RTNL semaphore
 *	or @dev_base_lock. If the name is found a pointer to the device
 *	is returned. If the name is not found then %NULL is returned. The
 *	reference counters are not incremented so the caller must be
 *	careful with locks.
 */

struct net_device *__dev_get_by_name(struct net *net, const char *name)
{
	struct hlist_node *p;
	struct net_device *dev;
	struct hlist_head *head = dev_name_hash(net, name);

	hlist_for_each_entry(dev, p, head, name_hlist)
		if (!strncmp(dev->name, name, IFNAMSIZ))
			return dev;

	return NULL;
}

/**
 *	dev_get_by_name		- find a device by its name
 *	@net: the applicable net namespace
 *	@name: name to find
 *
 *	Find an interface by name. This can be called from any
 *	context and does its own locking. The returned handle has
 *	the usage count incremented and the caller must use dev_put() to
 *	release it when it is no longer needed. %NULL is returned if no
 *	matching device is found.
 */

struct net_device *dev_get_by_name(struct net *net, const char *name)
{
	struct net_device *dev;

        read_lock(&dev_base_lock);
	dev = __dev_get_by_name(net, name);
	if (dev)
		dev_hold(dev);
        read_unlock(&dev_base_lock);
	return dev;
}

/**
 *	__dev_get_by_index - find a device by its ifindex
 *	@net: the applicable net namespace
 *	@ifindex: index of device
 *
 *	Search for an interface by index. Returns %NULL if the device
 *	is not found or a pointer to the device. The device has not
 *	had its reference counter increased so the caller must be careful
 *	about locking. The caller must hold either the RTNL semaphore
 *	or @dev_base_lock.
 */
struct net_device *__dev_get_by_index(struct net *net, int ifindex)
{
	struct hlist_node *p;
	struct net_device *dev;
	struct hlist_head *head = dev_index_hash(net, ifindex);

	hlist_for_each_entry(dev, p, head, index_hlist)
		if (dev->ifindex == ifindex)
			return dev;

	return NULL;
}

/**
 *	dev_get_by_index - find a device by its ifindex
 *	@net: the applicable net namespace
 *	@ifindex: index of device
 *
 *	Search for an interface by index. Returns NULL if the device
 *	is not found or a pointer to the device. The device returned has
 *	had a reference added and the pointer is safe until the user calls
 *	dev_put to indicate they have finished with it.
 */
struct net_device *dev_get_by_index(struct net *net, int ifindex)
{
	struct net_device *dev;

        read_lock(&dev_base_lock);
	dev = __dev_get_by_index(net, ifindex);
	if (dev)
		dev_hold(dev);
        read_unlock(&dev_base_lock);
	return dev;
}

static int list_netdevice(struct net_device *dev)
{
	write_lock(&dev_base_lock);
	list_add_tail(&dev->dev_list, &dev_base_head);
	hlist_add_head(&dev->name_hlist, dev_name_hash(&init_net, dev->name));
	hlist_add_head(&dev->index_hlist,
                       dev_index_hash(&init_net, dev->ifindex));
	write_unlock(&dev_base_lock);
	return 0;
}

static void unlist_netdevice(struct net_device *dev)
{
	/* Unlink dev from the device chain */
	write_lock(&dev_base_lock);
	list_del(&dev->dev_list);
	hlist_del(&dev->name_hlist);
	hlist_del(&dev->index_hlist);
	write_unlock(&dev_base_lock);
}

int register_netdev(struct net_device *dev)
{
        LOG_DBG("registering %s [%02x:%02x:%02x:%02x:%02x:%02x]\n",
                dev->name,
                dev->perm_addr[0],
                dev->perm_addr[1],
                dev->perm_addr[2],
                dev->perm_addr[3],
                dev->perm_addr[4],
                dev->perm_addr[5]);
        
        list_netdevice(dev);

        return 0;
}

void unregister_netdev(struct net_device *dev)
{
        LOG_DBG("unregistering %s\n", dev->name);
        unlist_netdevice(dev);
}

#if defined(OS_LINUX)
static int get_macaddr(const char *ifname, unsigned char mac[ETH_ALEN])
{
	struct ifreq ifr;
        int sock;
        
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        
        if (sock == -1) {
                LOG_ERR("Could not open sock: %s\n", strerror(errno));
                return -1;
        }
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

        if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
                LOG_ERR("could not get hw address of interface '%s'\n",
                        ifname);
        } else {
                memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        }

        close(sock);

        return 0;
}
#endif /* OS_LINUX */

/*
  Populate the device table at startup using getifaddrs. This is
  portable, but not dynamic (i.e., we cannot monitor interfaces that
  are removed).
  
  A better choice on Linux would be netlink, although this is not
  portable.
 */
int netdev_populate_table(int sizeof_priv, 
                          void (*setup)(struct net_device *))
{
        int ret = 0;
        struct ifaddrs *ifa = NULL, *tmp;
        
        ret = getifaddrs(&tmp);

        if (ret == -1) {
                LOG_ERR("could not get interface list\n");
                return ret;
        }

        for (ifa = tmp; ifa != NULL; ifa = ifa->ifa_next) {
                struct net_device *dev;
#if defined(OS_BSD)
                struct sockaddr_dl *ifaddr = 
                        (struct sockaddr_dl *)ifa->ifa_addr;
              
                if (ifaddr->sdl_family != AF_LINK)
                        continue;

                if (strncmp(ifa->ifa_name, "lo", 2) == 0)
                        continue;
                if (strncmp(ifa->ifa_name, "gif", 3) == 0)
                        continue;
                if (strncmp(ifa->ifa_name, "stf", 3) == 0)
                        continue;
                if (strncmp(ifa->ifa_name, "fw", 2) == 0)
                        continue;
#elif defined(OS_LINUX)
                /* Filter on all devices that support AF_PACKET, these
                   are the only ones we can use anyway. */
                if (ifa->ifa_addr->sa_family != AF_PACKET)
                        continue;
#endif
                /* Ignore loopback device */
                if (strncmp(ifa->ifa_name, "lo", 2) == 0)
                        continue;

                dev = alloc_netdev(sizeof_priv, ifa->ifa_name, setup);
                
                if (!dev)
                        continue;
                
                /* Figure out the mac address */
#if defined(OS_BSD)
                memcpy(dev->perm_addr, LLADDR(ifaddr), ETH_ALEN);
#elif defined(OS_LINUX)
                if (get_macaddr(ifa->ifa_name, dev->perm_addr) == -1) {
                        LOG_ERR("failed to get mac address for interface %s\n",
                                ifa->ifa_name);
                }
#endif          
                /* Mark as up */
                dev->flags |= IFF_UP;

                ret = register_netdev(dev);

                if (ret < 0) {
                        free_netdev(dev);
                        return ret;
                }
                
                service_add(NULL, 0, dev, GFP_KERNEL);

                ret = pthread_create(&dev->thr, NULL, dev_thread, dev);

                if (ret != 0) {
                        LOG_ERR("dev thread failure: %s\n",
                                strerror(errno));
                        unregister_netdev(dev);
                        free_netdev(dev);
                        return ret;
                }
        }
        
        freeifaddrs(tmp);
        
        return ret;
}

enum signal {
        SIGNAL_EXIT,
        SIGNAL_TXQUEUE,
        SIGNAL_ERROR,
        SIGNAL_UNKNOWN
};

int dev_signal(struct net_device *dev, enum signal type)
{
        unsigned char s = type & 0xff;
        struct pollfd fds;
        int ret;

        fds.fd = dev->pipefd[0];
        fds.events = POLLIN;
        
        ret = poll(&fds, 1, 0);

        /* Only write a new signal in case there is no signal
         * pending. */
        if (ret == 1)
                return 0;

        return write(dev->pipefd[1], &s, 1);
}

enum signal dev_read_signal(struct net_device *dev)
{
        unsigned char s;

        if (read(dev->pipefd[0], &s, 1) == -1)
                return SIGNAL_ERROR;

        if (s >= SIGNAL_UNKNOWN)
                return SIGNAL_UNKNOWN;

        return (enum signal)s;
}

int dev_xmit(struct net_device *dev)
{
        int n = 0;
        
        while (1) {
                struct sk_buff *skb = skb_dequeue(&dev->tx_queue.q);
        
                if (!skb)
                        break;

                if (skb->dev->pack_ops->xmit(skb) < 0) {
                        LOG_ERR("tx failed\n");
                }
        }

        /* LOG_DBG("sent %d packets\n", n); */
        
        return n;
}

void *dev_thread(void *arg)
{
        struct net_device *dev = (struct net_device *)arg;
        int ret = 0;
        
        LOG_DBG("Device thread '%s' running\n", dev->name);

        while (!dev->should_exit) {
                struct pollfd fds[2];
                
                fds[0].fd = dev->fd;
                fds[0].events = POLLIN | POLLHUP | POLLERR;
                fds[0].revents = 0;
                fds[1].fd = dev->pipefd[0];
                fds[1].events = POLLIN | POLLERR;
                fds[1].revents = 0;

                ret = poll(fds, 2, -1);

                if (ret == -1) {
                        LOG_ERR("poll error: %s\n", strerror(errno));
                        dev->should_exit = 1;
                } else if (ret == 0) {
                        /* No timeout set, should not happen */
                } else {
                        if (fds[1].revents & POLLIN) {
                                enum signal s = dev_read_signal(dev);

                                switch (s) {
                                case SIGNAL_EXIT:
                                        dev->should_exit = 1;
                                        LOG_DBG("dev thread %s should exit\n", 
                                                dev->name);
                                        break;
                                case SIGNAL_TXQUEUE:
                                        dev_xmit(dev);
                                        break;
                                default:
                                        LOG_ERR("bad signal %u\n", s);
                                }
                        } else if (fds[1].revents & POLLERR) {
                                LOG_ERR("signal error\n");
                        }
                        if (fds[0].revents) {
                                ret = dev->pack_ops->recv(dev);

                                if (ret == -1) {
                                        LOG_ERR("receive error on device %s\n",
                                                dev->name);
                                }
                        }
                }
        }
        return NULL;
}

int dev_queue_xmit(struct sk_buff *skb)
{
        struct net_device *dev = skb->dev;

        if (!dev || 
            !dev->pack_ops || 
            !dev->pack_ops->xmit) {
                free_skb(skb);
                return -1;
        }
        
        if (dev->tx_queue_len == dev->tx_queue.q.qlen) {
                free_skb(skb);
                LOG_ERR("Max tx_queue_len reached, dropping packet\n");
                return 0;
        }
        
        skb_queue_tail(&dev->tx_queue.q, skb);

        dev_signal(dev, SIGNAL_TXQUEUE);

        return 0;
}

int netdev_init(void)
{
	INIT_LIST_HEAD(&dev_base_head);
        
	dev_name_head = netdev_create_hash();

	if (dev_name_head == NULL)
		goto err_name;

	dev_index_head = netdev_create_hash();
	
        if (dev_index_head == NULL)
		goto err_idx;

	return 0;
err_idx:
	free(dev_name_head);
err_name:
	return -ENOMEM;
}

void netdev_fini(void)
{
        while (1) {
                struct net_device *dev;
                int ret;
                
                read_lock(&dev_base_lock);

                if (list_empty(&dev_base_head)) {
                        read_unlock(&dev_base_lock);
                        break;
                }
                dev = list_first_entry(&dev_base_head, 
                                       struct net_device, dev_list);
          	read_unlock(&dev_base_lock);       
                unregister_netdev(dev);
                
                dev_signal(dev, SIGNAL_EXIT);
                
                LOG_DBG("joining with device thread %s\n",
                        dev->name);

                ret = pthread_join(dev->thr, NULL);

                if (ret != 0) {
                        LOG_ERR("device thread join: %s\n",
                                strerror(errno));
                } else {
                        LOG_DBG("join successful\n");
                }
                dev_put(dev);
        }
}
