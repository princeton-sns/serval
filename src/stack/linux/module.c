/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <af_serval.h>
#include <serval/debug.h>
#include <serval/netdevice.h>
#include <linux/inetdevice.h>
#include <libstack/ctrlmsg.h>
#include <ctrl.h>
#include <service.h>
#include <neighbor.h>

MODULE_AUTHOR("Erik Nordstroem");
MODULE_DESCRIPTION("Serval socket API for Linux");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

/*
#if defined(ENABLE_DEBUG)
static uint debug = 0;
module_param(debug, uint, 0);
MODULE_PARM_DESC(debug, "Set debug level 0-5 (0=off).");
#endif
*/

extern int __init proc_init(void);
extern void __exit proc_fini(void);

static int serval_netdev_event(struct notifier_block *this,
                                 unsigned long event, void *ptr)
{
	struct net_device *dev = (struct net_device *)ptr;

        if (dev_net(dev) != &init_net)
                return NOTIFY_DONE;
        
        if (strncmp(dev->name, "lo", 2) == 0)
                return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:
        {
                struct net_addr dst;
                u32 mask = 0;
                unsigned int prefix_len = 0;

                dev_get_ipv4_broadcast(dev, &dst);

#if defined(ENABLE_DEBUG)
                {
                        char buf[16];
                        LOG_DBG("netdev UP %s bc=%s\n", 
                                dev->name, 
                                inet_ntop(AF_INET, &dst, buf, 16));
                }
#endif
                service_add(NULL, 0, dev, &dst, sizeof(dst), GFP_ATOMIC);

                dev_get_ipv4_netmask(dev, &mask);

                while (mask & (0x1 << prefix_len))
                       prefix_len++;

                neighbor_add(&dst, prefix_len, dev, dev->broadcast, 
                             dev->addr_len, GFP_ATOMIC);
                break;
        }
	case NETDEV_GOING_DOWN:
        {
                LOG_DBG("netdev GOING_DOWN %s\n", dev->name);
                service_del_dev(dev->name);
                //neighbor_del_dev(dev->name);
		break;
        }
	case NETDEV_DOWN:
                LOG_DBG("netdev DOWN\n");
                break;
	default:
		break;
	};

	return NOTIFY_DONE;
}

static int serval_inetaddr_event(struct notifier_block *this,
                                   unsigned long event, void *ptr)
{
	struct net_device *dev = (struct net_device *)ptr;

        if (dev_net(dev) != &init_net)
                return NOTIFY_DONE;
        
        if (strncmp(dev->name, "lo", 2) == 0)
                return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:
        {
       		LOG_DBG("inetdev UP %s\n", 
                        dev->name);
                break;
        }
	case NETDEV_GOING_DOWN:
        {
                LOG_DBG("inetdev GOING_DOWN %s\n", dev->name);
		break;
        }
	case NETDEV_DOWN:
                LOG_DBG("inetdev DOWN\n");
                break;
	default:
		break;
	};

	return NOTIFY_DONE;
}

static struct notifier_block netdev_notifier = {
	.notifier_call = serval_netdev_event,
};

static struct notifier_block inetaddr_notifier = {
	.notifier_call = serval_inetaddr_event,
};

int serval_module_init(void)
{
	int err = 0;

        LOG_DBG("Loaded serval protocol module\n");
        
        err = proc_init();
        
        if (err < 0) {
                LOG_CRIT("Cannot create proc entries\n");
                goto fail_proc;
        }

        err = ctrl_init();
        
	if (err < 0) {
                LOG_CRIT("Cannot create netlink control socket\n");
                goto fail_ctrl;
        }

	err = serval_init();

	if (err < 0) {
		 LOG_CRIT("Cannot initialize serval protocol\n");
		 goto fail_serval;
	}

	err = register_netdevice_notifier(&netdev_notifier);

	if (err < 0) {
                LOG_CRIT("Cannot register netdevice notifier\n");
                goto fail_netdev_notifier;
        }

	err = register_inetaddr_notifier(&inetaddr_notifier);

	if (err < 0) {
                LOG_CRIT("Cannot register inetaddr notifier\n");
                goto fail_inetaddr_notifier;
        }
out:
	return err;
fail_inetaddr_notifier:
        unregister_netdevice_notifier(&netdev_notifier);
fail_netdev_notifier:
        serval_fini();
fail_serval:
        ctrl_fini();
fail_ctrl:
        proc_fini();
fail_proc:
	goto out;
}

void __exit serval_module_fini(void)
{
        unregister_inetaddr_notifier(&inetaddr_notifier);
        unregister_netdevice_notifier(&netdev_notifier);
	serval_fini();
        ctrl_fini();
        proc_fini();
        LOG_INF("Unloaded serval protocol module\n");
}

module_init(serval_module_init)
module_exit(serval_module_fini)

MODULE_ALIAS_NETPROTO(PF_SERVAL);

