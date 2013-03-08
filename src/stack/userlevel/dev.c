/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/netdevice.h>
#include <serval/debug.h>
#include <serval/list.h>
#include <serval/hash.h>
#include <serval/net.h>
#include <serval/skbuff.h>
#include <netinet/serval.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
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
struct hlist_head *dev_name_head = NULL;
struct hlist_head *dev_index_head = NULL;
static void *dev_thread(void *arg);

/* A (white) list of interfaces to use. If empty, use all detected */
static struct list_head dev_list = { &dev_list , &dev_list };
struct dev_entry {
        struct list_head lh;
        char name[IFNAMSIZ];
};

/*
  This adds an interface to a white list. Unless the white list is
  empty, only the interfaces in the list will be used.
*/
void dev_list_add(const char *devnames)
{
        const char *sep = ",;";
        char *save_ptr, *str;
        char *buf;

        /* We need to make a copy, since strtok works only on
           non-const strings */
        buf = malloc(strlen(devnames) + 1);

        if (!buf)
                return;

        strcpy(buf, devnames);

        for (str = strtok_r(buf, sep, &save_ptr); str; 
             str = strtok_r(NULL, sep, &save_ptr)) {
                struct dev_entry *de;

                de = malloc(sizeof(struct dev_entry));

                if (de) {
                        INIT_LIST_HEAD(&de->lh);
                        strcpy(de->name, str);
                        list_add_tail(&de->lh, &dev_list);
                }
        }
        free(buf);
}

void dev_list_destroy(void)
{
        while (1) {
                struct dev_entry *de;
                
                if (list_empty(&dev_list))
                        break;

                de = list_first_entry(&dev_list, struct dev_entry, lh);
                list_del(&de->lh);                
                free(de);
        }
}

const char *dev_list_find(const char *name)
{
        struct dev_entry *de;

        list_for_each_entry(de, &dev_list, lh) {
                if (strcmp(name, de->name) == 0)
                        return de->name;
        }

        return NULL;
}

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

struct net_device *resolve_dev_impl(const struct in_addr *addr,
                                    int ifindex)
{
        struct net_device *dev = NULL, *best_guess_dev = NULL;
        struct hlist_node *p;
        int i;

        read_lock(&dev_base_lock);

        /* Find the best possible match by comparing prefixes */
	for (i = 0; i < NETDEV_HASHENTRIES; i++) {
                hlist_for_each_entry(dev, p, &dev_name_head[i], name_hlist) {
                        uint32_t prefix1 = addr->s_addr & dev->ipv4.netmask;
                        uint32_t prefix2 = dev->ipv4.addr & dev->ipv4.netmask;

                        if (prefix1 == prefix2) {
                                dev_hold(dev);
                                read_unlock(&dev_base_lock);
                                return dev;
                        }
                        if (!best_guess_dev && strcmp(dev->name, "lo") != 0)
                                best_guess_dev = dev;
                }
        }

        if (best_guess_dev)
                dev_hold(best_guess_dev);

        read_unlock(&dev_base_lock);

        /* Try with index if it is >= 0 */
        dev = ifindex >= 0 ? dev_get_by_index(&init_net, ifindex) : NULL;
        
        if (dev && best_guess_dev)
                dev_put(best_guess_dev);
        else
                dev = best_guess_dev;

        return dev;
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

	return dev;
}

static int init_netdev(struct net_device *dev)
{
        /* Call the packet handlers init function if it exists */
        if (dev->pack_ops && dev->pack_ops->init) {
                if (dev->pack_ops->init(dev) == -1) {
                        LOG_ERR("packet ops init failed for device %s\n",
                                dev->name);
                        return -1;
                }
        }
        return 0;
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

	if (ifindex == 0) {
                /* return the first device */
                if (list_empty(&dev_base_head))
                        return NULL;

                dev = list_entry(dev_base_head.next, 
                                 struct net_device, dev_list);
                return dev;
	}

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
        LOG_DBG("unregistered %s\n", dev->name);
}

#if defined(OS_LINUX)
static int get_macaddr(const char *ifname, unsigned char mac[ETH_ALEN])
{
	struct ifreq ifr;
        int sock, err;
                
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        
        if (sock == -1) {
                LOG_ERR("Could not open sock: %s\n", strerror(errno));
                return -1;
        }
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

        err = ioctl(sock, SIOCGIFHWADDR, &ifr);

        if (err == -1) {
                LOG_ERR("could not get hw address of interface '%s'\n",
                        ifname);
        } else {
                memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        }

        close(sock);

        return err;
}
#endif /* OS_LINUX */

/*
  Populate the device table at startup using SIOCGIFCONF ioctl. This
  is kind of portable, but not dynamic (i.e., we cannot monitor interfaces
  that are removed).
  
  We are not using getifaddrs, since that is not available on Android.

  A better choice on Linux would be netlink, although this is not
  portable.
 */

#define	MAX(a,b) ((a) > (b) ? (a) : (b))

int netdev_populate_table(int sizeof_priv, 
                          void (*setup)(struct net_device *))
{
        struct service_id default_service;
        int fd, len = 0, ret = 0;
        struct ifconf ifc;
	struct ifreq *ifr = NULL;
        char buff[8192];

        memset(&default_service, 0, sizeof(default_service));

        if (ret == -1) {
                LOG_ERR("could not get interface list\n");
                return ret;
        }

        fd = socket(AF_INET, SOCK_DGRAM, 0);

        if (fd == -1) {
		return -1;
	}
  
	ifc.ifc_len = sizeof(buff);
	ifc.ifc_buf = buff;

	if (ioctl(fd, SIOCGIFCONF, &ifc) != 0) {
		close(fd);
		return -1;
	} 

	ifr = ifc.ifc_req;

	/* Loop through interfaces */
	for (;ifc.ifc_len; 
             ifr = (struct ifreq *)((char*)ifr+len), 
                     ifc.ifc_len -= len) {
                struct net_device *dev;
                const char *name = ifr->ifr_name;
                int prefix_len = 0;
#if defined(OS_BSD)
                struct sockaddr_dl *ifaddr = 
                        (struct sockaddr_dl *)&ifr->ifr_addr;
              
                len = (sizeof(ifr->ifr_name) + MAX(sizeof(struct sockaddr),
                                                   ifr->ifr_addr.sa_len));
                
                if (ifaddr->sdl_family != AF_LINK)
                        continue;

                if (strncmp(name, "gif", 3) == 0)
                        continue;
                if (strncmp(name, "stf", 3) == 0)
                        continue;
                if (strncmp(name, "fw", 2) == 0)
                        continue;
#elif defined(OS_LINUX)
                len = sizeof(struct ifreq);
#endif

                /* If there are white listed interfaces, ignore all
                   interfaces not in the list, except the loopback
                   device (we need that for localhost
                   communication). */
                if (strncmp(name, "lo", 2) != 0 &&
                    !list_empty(&dev_list) && 
                    !dev_list_find(ifr->ifr_name))
                        continue;
                        
                if (ioctl(fd, SIOCGIFFLAGS, ifr) == -1) {
                        LOG_ERR("SIOCGIFFLAGS: %s\n",
                                strerror(errno));
                        goto out;
                }
                
                dev = alloc_netdev(sizeof_priv, ifr->ifr_name, setup);
                
                if (!dev)
                        continue;

                /* Figure out the mac address */
#if defined(OS_BSD)
                memcpy(dev->perm_addr, LLADDR(ifaddr), ETH_ALEN);
#elif defined(OS_LINUX)
                if (get_macaddr(name, dev->perm_addr) == -1) {
                        LOG_ERR("%s failed to get mac address\n",
                                name);
                }
#endif          
                /* Mark as up */
                if (ifr->ifr_flags & IFF_UP)
                        dev->flags |= IFF_UP;

                /* Get and save ip configuration */
                if (ioctl(fd, SIOCGIFADDR, ifr) == -1) {
                        LOG_ERR("SIOCGIFADDR: %s\n",
                                strerror(errno));
                        free_netdev(dev);
                        continue;
                }

                memcpy(&dev->ipv4.addr, 
                       &((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr, 4);
                                
                if (strncmp(name, "lo", 2) != 0 && 
                    ioctl(fd, SIOCGIFBRDADDR, ifr) == -1) {
                        LOG_ERR("SIOCGIFBRDADDR: %s\n",
                                strerror(errno));
                        free_netdev(dev);
                        continue;
                }

                memcpy(&dev->ipv4.broadcast, 
                       &((struct sockaddr_in *)&ifr->ifr_broadaddr)->sin_addr, 4);

                if (ioctl(fd, SIOCGIFNETMASK, ifr) == -1) {
                        LOG_ERR("SIOCGIFNETMASK: %s\n",
                                strerror(errno));
                        free_netdev(dev);
                        continue;
                }
#if defined(OS_LINUX)
                memcpy(&dev->ipv4.netmask, 
                       &((struct sockaddr_in *)&ifr->ifr_netmask)->sin_addr, 4);
#else
                memcpy(&dev->ipv4.netmask, 
                       &((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr, 4);
#endif

#if defined(ENABLE_DEBUG)
                {
                        char ip[18], broad[18], netmask[18];
                        LOG_DBG("%s [%d] %s/%s/%s\n",
                                dev->name,
                                dev->ifindex,
                                inet_ntop(AF_INET, &dev->ipv4.addr, ip, 18),
                                inet_ntop(AF_INET, &dev->ipv4.broadcast, 
                                          broad, 18),
                                inet_ntop(AF_INET, &dev->ipv4.netmask,
                                          netmask, sizeof(netmask)));
                }
#endif       

                ret = init_netdev(dev);
                
                if (ret < 0) {
                        free_netdev(dev);
                        continue;
                }

                ret = register_netdev(dev);

                if (ret < 0) {
                        free_netdev(dev);
                        continue;
                }

                while (dev->ipv4.netmask & (0x1 << prefix_len))
                       prefix_len++;
#if defined(ENABLE_DEBUG)
                {
                        char broad[18];

                        LOG_DBG("Adding default service rule pointing to %s\n",
                                inet_ntop(AF_INET, &dev->ipv4.broadcast,
                                          broad, sizeof(broad)));
                }
#endif
                service_add(&default_service, 0, SERVICE_RULE_FORWARD, 0, 
                            BROADCAST_SERVICE_DEFAULT_PRIORITY,
                            BROADCAST_SERVICE_DEFAULT_WEIGHT,  
                            &dev->ipv4.broadcast, 
                            sizeof(dev->ipv4.broadcast), make_target(dev), 0);

                ret = pthread_create(&dev->thr, NULL, dev_thread, dev);

                if (ret != 0) {
                    LOG_ERR("dev thread failure: %s\n",
                        strerror(errno));
                        unregister_netdev(dev);
                        free_netdev(dev);
                }
        }
/*
#if defined(ENABLE_DEBUG)
        {
                char buf[2000];
                services_print(buf, 2000);
                printf("%s\n", buf);
        }
#endif
*/      
out:
        close(fd);

        return ret;
}

enum signal_event {
        SIGNAL_EXIT,
        SIGNAL_TXQUEUE,
        SIGNAL_ERROR,
        SIGNAL_UNKNOWN
};

int dev_signal(struct net_device *dev, enum signal_event type)
{
        unsigned char s = type & 0xff;
        struct pollfd fds;
        int ret;

        if (dev->pipefd[1] == -1) {
                LOG_ERR("pipefd[1] == -1\n");
                return -1;
        }
                
        fds.fd = dev->pipefd[0];
        fds.events = POLLIN | POLLHUP | POLLERR;
        
        ret = poll(&fds, 1, 0);

        /* Only write a new signal in case there is no signal
         * pending. */
        if (ret == 1)
                return 0;
        
        return write(dev->pipefd[1], &s, 1);
}

int dev_get_ipv4_addr(struct net_device *dev, enum addr_type type, void *addr)
{
        switch (type) {
        case IFADDR_LOCAL:
                memcpy(addr, &dev->ipv4.addr, 4);
                break;
        case IFADDR_BROADCAST:
                memcpy(addr, &dev->ipv4.broadcast, 4);
                break;
        default:
                break;
        }
        return 1;
}

enum signal_event dev_read_signal(struct net_device *dev)
{
        unsigned char s;
        struct pollfd fds;

        fds.fd = dev->pipefd[0];
        fds.events = POLLIN | POLLHUP;
        
        if (poll(&fds, 1, 0) == -1)
                return SIGNAL_ERROR;
        
        if (fds.revents & POLLHUP)
                return SIGNAL_EXIT;
        
        if (fds.revents & POLLERR)
                return SIGNAL_ERROR;

        if (fds.revents & POLLIN) { 
                if (read(dev->pipefd[0], &s, 1) == -1)
                        return SIGNAL_ERROR;
        }

        if (s >= SIGNAL_UNKNOWN)
                return SIGNAL_UNKNOWN;

        return (enum signal_event)s;
}

static inline void dev_queue_purge(struct net_device *dev)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&dev->tx_queue.q)) != NULL) {
		LOG_DBG("Freeing skb %p\n", skb);
		kfree_skb(skb);
	}
}

int dev_xmit(struct net_device *dev)
{
        int n = 0;
        
        while (1) {
                struct sk_buff *skb = skb_dequeue(&dev->tx_queue.q);
        
                if (!skb)
                        break;
                
                if (skb->dev) {
                        if (skb->dev->pack_ops->xmit(skb) < 0) {
                                LOG_ERR("tx failed\n");
                        }
                } else {
                        LOG_ERR("No device set in skb\n");
                        kfree_skb(skb);
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
                fds[1].events = POLLIN | POLLERR | POLLHUP;
                fds[1].revents = 0;

                ret = poll(fds, 2, -1);

                if (ret == -1) {
                        if (errno == EINTR)
                                continue;

                        LOG_ERR("poll error: %s\n", strerror(errno));
                        dev->should_exit = 1;
                } else if (ret == 0) {
                        /* No timeout set, should not happen */
                } else {
                        if (fds[1].revents & POLLIN) {
                                enum signal_event s = dev_read_signal(dev);

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
                        } else if (fds[1].revents & POLLHUP) {
                                LOG_DBG("POLLHUP on pipe\n");
                        }
                        if (fds[0].revents & POLLIN) {
                                ret = dev->pack_ops->recv(dev);
                        } else if (fds[0].revents & POLLHUP) {
                                LOG_DBG("socket POLLHUP\n");
                        } else if (fds[0].revents & POLLERR) {
                                LOG_ERR("socket error\n");
                        }
                }
        }

        dev_queue_purge(dev);

        return NULL;
}

/*
 * Invalidate hardware checksum when packet is to be mangled, and
 * complete checksum manually on outgoing path.
 */
static int skb_checksum_help(struct sk_buff *skb)
{
        __wsum csum;
        int ret = 0, offset;

        if (skb->ip_summed == CHECKSUM_COMPLETE)
                goto out_set_summed;

        offset = skb_checksum_start_offset(skb);
        BUG_ON(offset >= skb_headlen(skb));
        csum = skb_checksum(skb, offset, skb->len - offset, 0);

        offset += skb->csum_offset;

        BUG_ON(offset + sizeof(__sum16) > skb_headlen(skb));

        if (skb_cloned(skb) &&
            !skb_clone_writable(skb, offset + sizeof(__sum16))) {
                ret = pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
                if (ret)
                        goto out;
        }

        *(__sum16 *)(skb->data + offset) = csum_fold(csum);

 out_set_summed:
        skb->ip_summed = CHECKSUM_NONE;
 out:
        return ret;
}

#define DIRECT_TX 1

int dev_queue_xmit(struct sk_buff *skb)
{
        struct net_device *dev = skb->dev;

        /*
          Calculate final checksum if partial 
        */
        if (skb->ip_summed == CHECKSUM_PARTIAL) {
                skb_set_transport_header(skb,
                                         skb_checksum_start_offset(skb));
                if (skb_checksum_help(skb))
                        goto out_kfree_skb;
        }

#if defined(DIRECT_TX)
        dev->pack_ops->xmit(skb);
#else
        if (!dev || 
            !dev->pack_ops || 
            !dev->pack_ops->xmit) {
                LOG_ERR("No device or packet ops\n");
                kfree_skb(skb);
                return -1;
        }
        
        if (dev->tx_queue_len == dev->tx_queue.q.qlen) {
                LOG_ERR("Max tx_queue_len reached, dropping packet\n");
                kfree_skb(skb);
                return 0;
        }
        
        skb_queue_tail(&dev->tx_queue.q, skb);

        /* TX immediately if we are on device thread */
        /* 
           if (pthread_equal(dev->thr, pthread_self()))
                dev_xmit(dev);
                else */
        dev_signal(dev, SIGNAL_TXQUEUE);
#endif
        return 0;
 out_kfree_skb:
        kfree_skb(skb);
        return -1;
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
        dev_name_head = NULL;
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
                     
                /*
                  service_del_dev(dev->name);
                */

                unregister_netdev(dev);

                dev_signal(dev, SIGNAL_EXIT);

                /* Queue should be purged already, but just to make
                 * sure. */
                dev_queue_purge(dev);

                LOG_DBG("joining with device thread %s\n",
                        dev->name);

                ret = pthread_join(dev->thr, NULL);

                if (ret != 0) {
                        LOG_ERR("device thread join: %s\n",
                                strerror(errno));
                } else {
                        LOG_DBG("join successful\n");
                }
                LOG_DBG("%s refcnt=%d\n", 
                        dev->name, atomic_read(&dev->refcnt));
                dev_put(dev);
        }
        
        dev_list_destroy();

        if (dev_name_head) {
                free(dev_name_head);
                dev_name_head = NULL;
        }

        if (dev_index_head) {
                free(dev_index_head);
                dev_index_head = NULL;
        }
}
