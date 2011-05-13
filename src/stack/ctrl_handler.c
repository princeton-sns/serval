/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/debug.h>
#include <serval/netdevice.h>
#include <libstack/ctrlmsg.h>
#include <service.h>
#include "ctrl.h"

extern int host_ctrl_mode;
extern atomic_t serval_transit;

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

static int ctrl_handle_add_service_msg(struct ctrlmsg *cm)
{
        struct ctrlmsg_resolution *cmr = (struct ctrlmsg_resolution *)cm;
        int num_res = CTRL_NUM_SERVICES(cmr, cmr->cmh.len);
#if defined(ENABLE_DEBUG)
        //char ipstr[20];
        LOG_DBG("adding %i services\n", num_res);
#endif         



        /* TODO - flags, etc */
        int i = 0;
        struct service_resolution* res;
        for(i = 0; i < num_res;i++) {
            res = &cmr->resolution[i];
            if (res->sv_prefix_bits > (sizeof(res->srvid)*8)) {
                res->sv_prefix_bits = (uint8_t) (sizeof(res->srvid) * 8);
            }

            service_add(&res->srvid, res->sv_prefix_bits, res->sv_flags, res->priority, res->weight,
                                       &res->address, sizeof(res->address),
                                       NULL, GFP_KERNEL);
        }

        /*TODO for now - assume all services added - best bet is to clear out invalid adds */
        ctrl_sendmsg(cm, GFP_KERNEL);
        return 0;
}


static int _ctrl_handle_add_service_msg(struct ctrlmsg *cm)
{
        struct ctrlmsg_service *cms = (struct ctrlmsg_service *)cm;
#if defined(ENABLE_DEBUG)
        char ipstr[20];
        LOG_DBG("adding service [%s] -> %s\n",
                service_id_to_str(&cms->srvid),
                inet_ntop(AF_INET, &cms->ipaddr,
                          ipstr, sizeof(ipstr)));
#endif
        if (cms->prefix_bits == 0 ||
            cms->prefix_bits > (sizeof(cms->srvid)*8)) {
                cms->prefix_bits = sizeof(cms->srvid) * 8;
        }

        return service_add(&cms->srvid, cms->prefix_bits, 0, LOCAL_SERVICE_DEFAULT_PRIORITY, LOCAL_SERVICE_DEFAULT_WEIGHT,
                           &cms->ipaddr, sizeof(cms->ipaddr),
                           NULL, GFP_KERNEL);
}


static int ctrl_handle_del_service_msg(struct ctrlmsg *cm)
{
        struct ctrlmsg_resolution *cmr = (struct ctrlmsg_resolution *)cm;
        struct in_addr *ip = NULL;
        uint32_t null_ip = 0;
        int num_res = CTRL_NUM_STAT_SERVICES(cmr, cmr->cmh.len);
#if defined(ENABLE_DEBUG)
        //char ipstr[20];
        LOG_DBG("deleting %i services\n", num_res);
#endif

        //int size = sizeof(struct ctrlmsg_resolution) + num_res * sizeof(struct service_resolution_stat);
        //struct ctrlmsg_resolution *cms = (struct ctrlmsg_resolution *) MALLOC(size, GFP_KERNEL);
        //if(!cms)
        //return 0;

        //memset(cms, 0, size);
        //cms->cmh.type = CTRLMSG_TYPE_DEL_SERVICE;

        int i = 0;
        //int j = 0;
        struct dest_stats dstat;
        //struct service_resolution*res;
        struct service_resolution_stat *stats = (struct service_resolution_stat*) &cmr->resolution;
        struct service_resolution_stat *sres;
        struct service_entry* se;
        int err = 0;
        for(i = 0; i < num_res;i++) {
            //sres = &cmr->resolution[i];
            sres = &stats[i];

            if (sres->res.sv_prefix_bits > (sizeof(sres->res.srvid)*8)) {
                sres->res.sv_prefix_bits = (uint8_t) (sizeof(sres->res.srvid) * 8);
            }

            if (memcmp(&sres->res.address, &null_ip, sizeof(sres->res.address)) != 0) {
                    ip = &sres->res.address.net_un.un_ip;
            }

            se = service_find(&sres->res.srvid, sres->res.sv_prefix_bits);

            if(!se)
                continue;


            memset(&dstat, 0, sizeof(dstat));
            err = service_entry_remove_dest(se, ip, ip ? sizeof(sres->res.address) : 0, &dstat);

            if(err > 0) {
                //sres = &stats[j++];
                //memcpy(&sres->res, res, sizeof(*res));
                sres->duration_sec = dstat.duration_sec;
                sres->duration_nsec = dstat.duration_nsec;
                //tokens too?
                sres->packets_resolved = dstat.packets_resolved;
                sres->bytes_resolved = dstat.bytes_resolved;
                sres->packets_dropped = dstat.packets_dropped;
                sres->bytes_dropped = dstat.packets_dropped;
            }

            service_entry_put(se);
        }

        //cms->cmh.len = sizeof(*cms) + j * sizeof(struct service_resolution_stat);
        //ctrl_sendmsg(&cms->cmh, GFP_KERNEL);
        ctrl_sendmsg(cm, GFP_KERNEL);
        //FREE(cms);
        return 0;
}

static int ctrl_handle_set_transit_msg(struct ctrlmsg *cm)
{
    struct ctrlmsg_set_transit *cmt = (struct ctrlmsg_set_transit*)cm;
    atomic_set(&serval_transit, cmt->transit);
    return 0;
}

static int ctrl_handle_mod_service_msg(struct ctrlmsg *cm)
{
        struct ctrlmsg_resolution *cmr = (struct ctrlmsg_resolution *)cm;
        struct in_addr *ip = NULL;
        uint32_t null_ip = 0;
        int num_res = CTRL_NUM_SERVICES(cmr, cmr->cmh.len);
#if defined(ENABLE_DEBUG)
        //char ipstr[20];
        LOG_DBG("modifying %i services\n", num_res);
#endif

        int i = 0;
        struct service_resolution*res;
        for(i = 0; i < num_res;i++) {
            res= &cmr->resolution[i];
            if (res->sv_prefix_bits > (sizeof(res->srvid)*8)) {
                res->sv_prefix_bits = (uint8_t) (sizeof(res->srvid) * 8);
            }

            if (memcmp(&res->address, &null_ip, sizeof(res->address)) != 0) {
                    ip = &res->address.net_un.un_ip;
            }

            service_modify(&res->srvid, res->sv_prefix_bits, res->sv_flags, res->priority, res->weight, ip, ip ? sizeof(res->address) : 0, NULL);
//            service_del_dest(&res->srvid, res->sv_prefix_bits,
//                             ip, ip ? sizeof(res->address) : 0);
        }

        /*TODO for now - assume all services added - best bet is to clear out invalid mods */
        ctrl_sendmsg(cm, GFP_KERNEL);
        return 0;
}

static int ctrl_handle_get_service_msg(struct ctrlmsg *cm)
{
        struct ctrlmsg_get_service *cmg = (struct ctrlmsg_get_service *)cm;


#if defined(ENABLE_DEBUG)
        //char ipstr[20];
        LOG_DBG("getting service: %s\n", service_id_to_str(&cmg->srvid));
#endif

        struct service_entry *se = service_find(&cmg->srvid, cmg->sv_prefix_bits);

        if(se) {

            struct service_resolution_iter iter;
            int i = 0;
            struct service_resolution* res;
            struct dest* dst;
            memset(&iter, 0, sizeof(iter));

            int size = sizeof(struct ctrlmsg_resolution) + se->count * sizeof(struct service_resolution);

            struct ctrlmsg_resolution* cres = (struct ctrlmsg_resolution* ) MALLOC(size, GFP_KERNEL);

            if(!cres) {
                service_entry_put(se);
                return 0;
            }

            memset(cres, 0, size);
            cres->cmh.type = CTRLMSG_TYPE_GET_SERVICE;
            cres->cmh.len = size;
            cres->xid = cmg->xid;

            service_resolution_iter_init(&iter, se, 1);

            while((dst = service_resolution_iter_next(&iter)) != NULL) {
                res = &cres->resolution[i++];

                memcpy(&res->srvid, &cmg->srvid, sizeof(cmg->srvid));
                memcpy(&res->address, dst->dst, dst->dstlen);
                res->sv_prefix_bits = cmg->sv_prefix_bits;
                res->sv_flags = cmg->sv_flags;
                res->weight = dst->weight;
                //TODO res->priority =
            }

            service_resolution_iter_destroy(&iter);
            service_entry_put(se);

            ctrl_sendmsg(&cres->cmh, GFP_KERNEL);
            FREE(cres);
        }
        else {
            cmg->sv_flags = SVSF_INVALID;
            ctrl_sendmsg(&cmg->cmh, GFP_KERNEL);
        }
        return 0;
}


static int _ctrl_handle_del_service_msg(struct ctrlmsg *cm)
{
        struct ctrlmsg_service *cms = (struct ctrlmsg_service *)cm;
        struct in_addr *ip = NULL;
        uint32_t null_ip = 0;
#if defined(ENABLE_DEBUG)
        char ipstr[20];
        LOG_DBG("deleting service [%s] -> %s\n",
                service_id_to_str(&cms->srvid),
                inet_ntop(AF_INET, &cms->ipaddr,
                          ipstr, sizeof(ipstr)));
#endif         
        if (cms->prefix_bits == 0 ||
            cms->prefix_bits > (sizeof(cms->srvid)*8)) {
                cms->prefix_bits = sizeof(cms->srvid) * 8;
        }

        if (memcmp(&cms->ipaddr, &null_ip, sizeof(cms->ipaddr)) != 0) {
                ip = &cms->ipaddr;
        }

        service_del_dest(&cms->srvid, cms->prefix_bits,
                         ip, ip ? sizeof(cms->ipaddr) : 0, NULL);

        return 0;
}

static int ctrl_handle_service_stats_msg(struct ctrlmsg *cm)
{
    struct ctrlmsg_stats *cms = (struct ctrlmsg_stats*)cm;

    memset(&cms->stats, 0, sizeof(cms->stats));
    if(atomic_read(&serval_transit)) {
        cms->stats.capabilities = SVSTK_TRANSIT;
    }

    struct table_stats tstats;
    memset(&tstats, 0, sizeof(tstats));

    service_get_stats(&tstats);

    cms->stats.instances = tstats.instances;
    cms->stats.bytes_resolved = tstats.bytes_resolved;
    cms->stats.packets_resolved = tstats.packets_resolved;
    cms->stats.bytes_dropped = tstats.bytes_dropped;
    cms->stats.packets_dropped = tstats.packets_dropped;

    ctrl_sendmsg(&cms->cmh, GFP_KERNEL);
    return 0;
}

ctrlmsg_handler_t handlers[] = {
        dummy_ctrlmsg_handler,
        dummy_ctrlmsg_handler,
        dummy_ctrlmsg_handler,
        dummy_ctrlmsg_handler,
        dummy_ctrlmsg_handler,
        ctrl_handle_iface_conf_msg,
        ctrl_handle_add_service_msg,
        ctrl_handle_del_service_msg,
        ctrl_handle_mod_service_msg,
        ctrl_handle_get_service_msg,
        ctrl_handle_service_stats_msg,
        ctrl_handle_set_transit_msg
};
