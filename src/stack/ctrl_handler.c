/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/debug.h>
#include <serval/platform.h>
#include <serval/netdevice.h>
#include <libstack/ctrlmsg.h>
#include <service.h>
#include "ctrl.h"

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

        /* Nothing really done here a.t.m. */
        dev_put(dev);

        return ret;
}

static int ctrl_handle_add_service_msg(struct ctrlmsg *cm)
{
        struct ctrlmsg_service *cmr = (struct ctrlmsg_service *)cm;
        unsigned int num_res = CTRLMSG_SERVICE_NUM(cmr);
        /* TODO - flags, etc */
        unsigned int i, index = 0;
        int err = 0;

        LOG_DBG("adding %u services, msg size %u\n", 
                num_res, sizeof(*cmr));

        for (i = 0; i < num_res; i++) {
                struct net_device* dev;
                struct service_info *entry = &cmr->services[i];
   
                if (entry->service.sv_prefix_bits == 0) {
                        entry->service.sv_prefix_bits = 0xff;
                }

                dev = dev_get_by_index(NULL, entry->if_index);

#if defined(ENABLE_DEBUG)
                {
                        char ipstr[18];
                        LOG_DBG("Adding service id: %s(%u) "
                                "@ address %s, priority %u, weight %u\n", 
                                service_id_to_str(&entry->service.sv_srvid), 
                                entry->service.sv_prefix_bits, 
                                inet_ntop(AF_INET, &entry->address,
                                          ipstr, sizeof(ipstr)),
                                entry->priority, entry->weight);
                }
#endif
                err = service_add(&entry->service.sv_srvid, 
                                  entry->service.sv_prefix_bits, 
                                  entry->service.sv_flags, 
                                  entry->priority, 
                                  entry->weight,
                                  &entry->address, 
                                  sizeof(entry->address),
                                  dev, GFP_KERNEL);

                if (dev)
                        dev_put(dev);

                if (err > 0) {
                        if (index < i) {
                                /*copy it over */
                                memcpy(&cmr->services[index], 
                                       entry, sizeof(*entry));
                        }
                        index++;
                } else {
                        LOG_ERR("Error adding service: %i\n", err);
                }
        }

        cm->len = CTRLMSG_SERVICE_LEN(index);
        ctrl_sendmsg(cm, GFP_KERNEL);

        return 0;
}

static int ctrl_handle_del_service_msg(struct ctrlmsg *cm)
{
        struct ctrlmsg_service *cmr = (struct ctrlmsg_service *)cm;
        unsigned int num_res = CTRLMSG_SERVICE_NUM(cmr);
        unsigned char buffer[sizeof(struct ctrlmsg_service_stat) + 
                             sizeof(struct service_info_stat) * (num_res - 1)];
        struct ctrlmsg_service_stat *cms = 
                (struct ctrlmsg_service_stat *)buffer;
        struct in_addr *ip = NULL;
        uint32_t null_ip = 0;
        unsigned int i = 0;
        int index = 0;
        struct dest_stats dstat;
        int err = 0;

#if defined(ENABLE_DEBUG)
        //char ipstr[20];
        LOG_DBG("deleting %u services\n", num_res);
#endif

        for (i = 0; i < num_res; i++) {
                struct service_info *entry = &cmr->services[i];
                struct service_info_stat *stat = &cms->services[index];
                struct service_entry *se;

                if (entry->service.sv_prefix_bits > 
                    (uint8_t)(sizeof(entry->service.sv_srvid)*8)) {
                        entry->service.sv_prefix_bits = 
                                (sizeof(entry->service.sv_srvid) * 8) 
                                & 0xff;
                }

                if (memcmp(&entry->address, &null_ip, 
                           sizeof(entry->address)) != 0) {
                        ip = &entry->address.net_un.un_ip;
                }

                se = service_find(&entry->service.sv_srvid, 
                                  entry->service.sv_prefix_bits);

                if (!se)
                        continue;

                memset(&dstat, 0, sizeof(dstat));
                err = service_entry_remove_dest(se, ip, ip ? 
                                                sizeof(entry->address) : 0, 
                                                &dstat);

                if (err > 0) {
                        //entry = &stats[j++];
                        //memcpy(&entry->res, res, sizeof(*res));
                        stat->duration_sec = dstat.duration_sec;
                        stat->duration_nsec = dstat.duration_nsec;
                        //tokens too?
                        stat->packets_resolved = dstat.packets_resolved;
                        stat->bytes_resolved = dstat.bytes_resolved;
                        stat->packets_dropped = dstat.packets_dropped;
                        stat->bytes_dropped = dstat.packets_dropped;

                        if (index < i) {
                                memcpy(&stat->service, entry, 
                                       sizeof(*entry));
                        }
                        index++;
                } else {
                        LOG_ERR("Could not remove service %s: %d\n", 
                                service_id_to_str(&entry->service.sv_srvid), 
                                err);
                }

                service_entry_put(se);
        }

        cm->len = sizeof(*cms) + (index-1) * sizeof(struct service_info_stat);
        ctrl_sendmsg(cm, GFP_KERNEL);

        return 0;
}

static int ctrl_handle_capabilities_msg(struct ctrlmsg *cm)
{
        struct ctrlmsg_capabilities *cmt = (struct ctrlmsg_capabilities*)cm;
        atomic_set(&serval_transit, cmt->capabilities & SVSTK_TRANSIT);
        return 0;
}

static int ctrl_handle_mod_service_msg(struct ctrlmsg *cm)
{
        struct ctrlmsg_service *cmr = (struct ctrlmsg_service *)cm;
        struct in_addr *ip = NULL;
        uint32_t null_ip = 0;
        int num_res = CTRLMSG_SERVICE_NUM(cmr);
        int i, index = 0;
        int err = 0;

#if defined(ENABLE_DEBUG)
        //char ipstr[20];
        LOG_DBG("modifying %i services\n", num_res);
#endif

        for (i = 0; i < num_res; i++) {
                struct service_info *entry = &cmr->services[i];
                if (entry->service.sv_prefix_bits > 
                    (uint8_t)(sizeof(entry->service.sv_srvid)*8)) {
                        entry->service.sv_prefix_bits = 
                                (sizeof(entry->service.sv_srvid) * 8) & 0xff;
                }

                if (memcmp(&entry->address, &null_ip, 
                           sizeof(entry->address)) != 0) {
                        ip = &entry->address.net_un.un_ip;
                }

                LOG_DBG("Modifying: %s flags(%i) bits(%i)\n", 
                        service_id_to_str(&entry->service.sv_srvid), 
                        entry->service.sv_flags, 
                        entry->service.sv_prefix_bits);
                
                err = service_modify(&entry->service.sv_srvid, 
                                     entry->service.sv_prefix_bits, 
                                     entry->service.sv_flags, 
                                     entry->priority, 
                                     entry->weight, 
                                     ip, 
                                     ip ? sizeof(entry->address) : 0, NULL);
                if (err > 0) {
                        if (index < i) {
                                /*copy it over */
                                memcpy(&cmr->services[index], 
                                       entry, sizeof(*entry));
                        }
                        index++;
                } else {
                        LOG_ERR("Could not modify service %s: %i\n", 
                                service_id_to_str(&entry->service.sv_srvid), 
                                err);
                }
        }

        cm->len = CTRLMSG_SERVICE_LEN(index);
        ctrl_sendmsg(cm, GFP_KERNEL);

        return 0;
}

static int ctrl_handle_get_service_msg(struct ctrlmsg *cm)
{
        struct ctrlmsg_service *cmg = (struct ctrlmsg_service *)cm;
        struct service_entry *se;
        struct service_resolution_iter iter;
        struct dest *dst;
        int i = 0;

#if defined(ENABLE_DEBUG)
        //char ipstr[20];
        LOG_DBG("getting service: %s\n",
                service_id_to_str(&cmg->services[0].service.sv_srvid));
#endif
        se = service_find(&cmg->services[0].service.sv_srvid, 
                          cmg->services[0].service.sv_prefix_bits);

        if (se) {
                int size = sizeof(struct ctrlmsg_service) + 
                        se->count * sizeof(struct service_entry);
                struct ctrlmsg_service *cres = 
                        (struct ctrlmsg_service *)MALLOC(size, GFP_KERNEL);

                if (!cres) {
                        service_entry_put(se);
                        return -ENOMEM;
                }

                memset(cres, 0, size);
                cres->cmh.type = CTRLMSG_TYPE_GET_SERVICE;
                cres->cmh.len = size;
                cres->xid = cmg->xid;

                memset(&iter, 0, sizeof(iter));
                service_resolution_iter_init(&iter, se, 1);

                while ((dst = service_resolution_iter_next(&iter)) != NULL) {
                        struct service_info *entry = &cres->services[i++];
                        
                        memcpy(&entry->service.sv_srvid, 
                               &cmg->services[0].service.sv_srvid, 
                               sizeof(cmg->services[0].service.sv_srvid));
                        memcpy(&entry->address, 
                               dst->dst, dst->dstlen);
                        entry->service.sv_prefix_bits = 
                                cmg->services[0].service.sv_prefix_bits;
                        entry->service.sv_flags = 
                                service_resolution_iter_get_flags(&iter);
                        entry->weight = dst->weight;
                        entry->priority = 
                                service_resolution_iter_get_priority(&iter);
                }

                service_resolution_iter_destroy(&iter);
                service_entry_put(se);

                ctrl_sendmsg(&cres->cmh, GFP_KERNEL);
                FREE(cres);
        } else {
                cmg->services[0].service.sv_flags = SVSF_INVALID;
                ctrl_sendmsg(&cmg->cmh, GFP_KERNEL);
        }

        return 0;
}

static int ctrl_handle_service_stats_msg(struct ctrlmsg *cm)
{
        struct ctrlmsg_service_stats *cms = (struct ctrlmsg_service_stats *)cm;
        struct table_stats tstats;

        memset(&cms->stats, 0, sizeof(cms->stats));
        
        if (atomic_read(&serval_transit)) {
                cms->stats.capabilities = SVSTK_TRANSIT;
        }

        memset(&tstats, 0, sizeof(tstats));

        service_get_stats(&tstats);

        cms->stats.instances = tstats.instances;
        cms->stats.services = tstats.services;
        cms->stats.bytes_resolved = tstats.bytes_resolved;
        cms->stats.packets_resolved = tstats.packets_resolved;
        cms->stats.bytes_dropped = tstats.bytes_dropped;
        cms->stats.packets_dropped = tstats.packets_dropped;

        LOG_DBG("service stats: instances(%i) services(%i) "
                "bytes resolved(%i) packets resolved(%i) capabilities\n",
                tstats.instances, tstats.services, tstats.bytes_resolved,
                tstats.packets_resolved, cms->stats.capabilities);

        ctrl_sendmsg(&cms->cmh, GFP_KERNEL);

        return 0;
}

ctrlmsg_handler_t handlers[] = {
        dummy_ctrlmsg_handler,
        dummy_ctrlmsg_handler,
        dummy_ctrlmsg_handler,
        ctrl_handle_iface_conf_msg,
        ctrl_handle_add_service_msg,
        ctrl_handle_del_service_msg,
        ctrl_handle_mod_service_msg,
        ctrl_handle_get_service_msg,
        ctrl_handle_service_stats_msg,
        ctrl_handle_capabilities_msg
};
