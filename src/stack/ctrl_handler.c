/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/debug.h>
#include <scaffold/netdevice.h>
#include <libstack/ctrlmsg.h>
#include "ctrl.h"

static int dummy_ctrlmsg_handler(struct ctrlmsg *cm)
{
	LOG_DBG("control message type %u\n", cm->type);
        return 0;
}

static int ctrl_handle_iface_conf_msg(struct ctrlmsg *cm)
{
        struct ctrlmsg_iface_conf *ifcm = (struct ctrlmsg_iface_conf *)cm;
        struct net_device *dev;
        int ret = 0;

        dev = dev_get_by_name(&init_net, ifcm->ifname);

        if (!dev) {
                LOG_ERR("No interface %s\n", ifcm->ifname);
                return -1;
        }

        LOG_DBG("iface %s as=%u host=%u\n", 
                ifcm->ifname,
                ifcm->asaddr.s_addr,
                ifcm->haddr.s_addr);

        /* Configure as and host addr */

        dev_put(dev);
        
        return ret;
}

ctrlmsg_handler_t handlers[] = {
        dummy_ctrlmsg_handler,
        dummy_ctrlmsg_handler,
        dummy_ctrlmsg_handler,
        dummy_ctrlmsg_handler,
        ctrl_handle_iface_conf_msg,
};
