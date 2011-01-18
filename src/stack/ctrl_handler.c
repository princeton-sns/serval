/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/debug.h>
#include <scaffold/netdevice.h>
#include <libstack/ctrlmsg.h>
#include "ctrl.h"

extern int host_ctrl_mode;

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

        LOG_DBG("iface %s\n", ifcm->ifname);


        /* TODO: Currently host control mode is on a per interface
         * basis, but we have a global control flag. We need a better
         * way to figure out the stack's control mode. */
        if (ifcm->flags & IFFLAG_HOST_CTRL_MODE) {
                LOG_DBG("setting host control mode\n");
                host_ctrl_mode = 1;
        } else {
                host_ctrl_mode = 0;
        }

        dev_put(dev);
        
        return ret;
}

static int ctrl_handle_set_service_msg(struct ctrlmsg *cm)
{
        LOG_DBG("\n");
         
        return 0;
}

ctrlmsg_handler_t handlers[] = {
        dummy_ctrlmsg_handler,
        dummy_ctrlmsg_handler,
        dummy_ctrlmsg_handler,
        dummy_ctrlmsg_handler,
        ctrl_handle_iface_conf_msg,
        ctrl_handle_set_service_msg
};
