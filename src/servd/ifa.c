/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <serval/list.h>
#include <arpa/inet.h>
#include <common/timer.h>
#include <common/debug.h>
#include "ifa.h"

/*
  Interface discovery on platforms that have ifaddrs support, but
  no event-based mechanism for interface events (e.g., up/down).

  This implementation uses a poll-based approach using timers. It
  essentially discovers all interfaces at regular intervals and
  assesses the difference between the current and last discovery to
  see which interfaces have gone up or down.
 */

extern int servd_interface_up(const char *ifname, 
                              const struct in_addr *new_ip,
                              const struct in_addr *old_ip,
                              void *arg);

static const char *blacklist[] = {
        "lo",
        NULL        
};

struct interface {
	struct list_head lh;
	char name[IFNAMSIZ];
        int alive;
};

static struct list_head interface_list = { &interface_list, &interface_list };
static struct timer *iftimer;
static struct timer_queue *timer_q = NULL;

static int is_blacklist_interface(const char *ifname)
{
        int i = 0;

        while (blacklist[i]) {
                int len = strlen(blacklist[i]);
                if (strncmp(blacklist[i], ifname, len) == 0)
                        return 1;
                i++;
        }
        return 0;
}

static struct interface *interface_list_find(const char *ifname)
{
	struct interface *iface;

	list_for_each_entry(iface, &interface_list, lh) {
		if (strcmp(iface->name, ifname) == 0) {
			iface->alive = 1;
                        return iface;
                }
	}
	return NULL;
}

static int interface_list_add(const char *ifname)
{
	struct interface *iface;

	if (interface_list_find(ifname))
		return 0;
	
	iface = (struct interface *)malloc(sizeof(*iface));

        if (!iface)
                return -1;

	memset(iface, 0, sizeof(*iface));
	strncpy(iface->name, ifname, sizeof(iface->name));
	INIT_LIST_HEAD(&iface->lh);
        iface->alive = 1;
	list_add(&iface->lh, &interface_list);
	
	return 1;
}

/*
static int interface_list_del(const char *ifname)
{
	struct interface *iface = interface_list_find(ifname);

	if (!iface)
		return 0;

	list_del(&iface->lh);

	free(iface);

	return 1;
}
*/

static int interface_list_remove_stale(void)
{
        struct interface *iface, *tmp;
        int num = 0;
        
        list_for_each_entry_safe(iface, tmp, &interface_list, lh) {
		if (iface->alive) {
                        /* Reset alive flag, so that it is set only if
                         * the interface is discovered again next
                         * time. */
                        iface->alive = 0;
                } else {
                        LOG_DBG("interface %s down\n", iface->name);
                        list_del(&iface->lh);
                        free(iface);
                        num++;
                }
	}

        return num;
}

static int ifaddrs_find(void)
{
	struct ifaddrs *ifa, *it;
	int ret;      

	ret = getifaddrs(&ifa);

	if (ret == -1) {
		fprintf(stderr, "getifaddrs failure: %s\n",
			strerror(errno));
		return ret;
	}

	for (it = ifa; it != NULL; it = it->ifa_next) {
		if (it->ifa_addr &&
                    it->ifa_addr->sa_family == AF_INET) {
                        if (is_blacklist_interface(it->ifa_name))
                                continue;
                        
                        if (it->ifa_flags & IFF_UP) {
				if (interface_list_add(it->ifa_name) == 1) {
                                        /*
                                        servd_interface_up(ifi->ifname,
                                                           &ifi->ipaddr.sin_addr,
                                                           &ifi2->ipaddr.sin_addr,
                                                           nlh->data);
                                        */
				}
			}
		}
	}
	
        interface_list_remove_stale();

	freeifaddrs(ifa);

	return ret;
}

static void ifaddrs_timer_timeout(struct timer *t)
{
	ifaddrs_find();
        timer_schedule_secs(timer_q, iftimer, 5);
}

int ifaddrs_init(struct timer_queue *tq)
{
        timer_q = tq;

	ifaddrs_find();

	iftimer = timer_new_callback(ifaddrs_timer_timeout, NULL);

	if (!iftimer)
		return -1;

        return timer_schedule_secs(tq, iftimer, 5);
}

void ifaddrs_fini(struct timer_queue *tq)
{
	if (iftimer) {
                timer_del(tq, iftimer);
		timer_free(iftimer);
        }
}
