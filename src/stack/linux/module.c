/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/net.h>
#include <af_scaffold.h>
#include <scaffold/debug.h>
#include "scaffold_netlink.h"

MODULE_AUTHOR("Erik Nordstroem");
MODULE_DESCRIPTION("Scaffold socket API for Linux");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

#define RTO_INITIAL_DISABLED 0 // Use whatever value is set by default
static uint rto = RTO_INITIAL_DISABLED;
static int rto_dynamic = 0;
static uint tx_burst = 0;

module_param(rto, uint, 0);
MODULE_PARM_DESC(rto, "Set initial RTO value (micro seconds).");

module_param(rto_dynamic, int, 0);
MODULE_PARM_DESC(rto_dynamic, "Enable dynamic RTO using Van Jacobson's algorithm.");

module_param(tx_burst, uint, 0);
MODULE_PARM_DESC(tx_burst, "Maximum packets the transmit task sends in one burst (0 = use default value).");

#if defined(ENABLE_DEBUG)
static uint debug = 0;
module_param(debug, uint, 0);
MODULE_PARM_DESC(debug, "Set debug level 0-5 (0=off).");
#endif

static int scaffold_netdev_event(struct notifier_block *this,
                                 unsigned long event, void *ptr)
{
	struct net_device *dev = (struct net_device *)ptr;

        if (dev->nd_net != &init_net)
                return NOTIFY_DONE;
        
	switch (event) {
	case NETDEV_UP:
		LOG_DBG("Netdev UP %s\n", dev->name);
		break;
	case NETDEV_GOING_DOWN:
		LOG_DBG("Netdev GOING_DOWN %s\n", dev->name);
                break;
	case NETDEV_DOWN:
                LOG_DBG("Netdev DOWN\n");
                break;
	default:
		break;
	};

	return NOTIFY_DONE;
}

static struct notifier_block netdev_notifier = {
	.notifier_call = scaffold_netdev_event,
};

int scaffold_module_init(void)
{
	int err = 0;

        LOG_DBG("Loaded scaffold protocol module\n");
       
	err = register_netdevice_notifier(&netdev_notifier);

	if (err < 0) {
                LOG_CRIT("Cannot register netdevice notifier\n");
                goto fail_netdev_notifier;
        }
        err = scaffold_netlink_init();
        
	if (err < 0) {
                LOG_CRIT("Cannot create netlink socket\n");
                goto fail_netlink;
        }

	err = scaffold_init();

	if (err < 0) {
		 LOG_CRIT("Cannot create netlink socket\n");
		 goto fail_scaffold;
	}
out:
	return err;
fail_scaffold:
        scaffold_netlink_fini();
fail_netlink:
        unregister_netdevice_notifier(&netdev_notifier);
fail_netdev_notifier:
	goto out;
}

void __exit scaffold_module_fini(void)
{
	scaffold_fini();
        scaffold_netlink_fini();
        unregister_netdevice_notifier(&netdev_notifier);

        LOG_INF("Unloaded scaffold protocol module\n");
}

module_init(scaffold_module_init)
module_exit(scaffold_module_fini)

MODULE_ALIAS_NETPROTO(PF_SCAFFOLD);

