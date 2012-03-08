/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- 
 *
 * Handlers for Serval's control channel.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#include <serval/debug.h>
#include <serval/platform.h>
#include <serval/netdevice.h>
#include <serval/ctrlmsg.h>
#include <service.h>
#if defined(OS_LINUX_KERNEL)
#include <net/route.h>
#endif
#include "af_serval.h"
#include "ctrl.h"
#include "serval_sock.h"
#include "serval_sal.h"
#include "serval_ipv4.h"

static const char *ctrlmsg_str[] = {
        [CTRLMSG_TYPE_REGISTER] = "CTRLMSG_TYPE_REGISTER",
        [CTRLMSG_TYPE_UNREGISTER] = " CTRLMSG_TYPE_UNREGISTER",
        [CTRLMSG_TYPE_RESOLVE] = "CTRLMSG_TYPE_RESOLVE",
        [CTRLMSG_TYPE_ADD_SERVICE] = "CTRLMSG_TYPE_ADD_SERVICE",
        [CTRLMSG_TYPE_DEL_SERVICE] = "CTRLMSG_TYPE_DEL_SERVICE",
        [CTRLMSG_TYPE_MOD_SERVICE] = "CTRLMSG_TYPE_MOD_SERVICE",
        [CTRLMSG_TYPE_GET_SERVICE] = "CTRLMSG_TYPE_GET_SERVICE",
        [CTRLMSG_TYPE_SERVICE_STAT] = "CTRLMSG_TYPE_SERVICE_STAT",
        [CTRLMSG_TYPE_CAPABILITIES] = "CTRLMSG_TYPE_CAPABILITIES",
        [CTRLMSG_TYPE_MIGRATE] = "CTRLMSG_TYPE_MIGRATE",
        [CTRLMSG_TYPE_DUMMY] = "CTRLMSG_TYPE_DUMMY",
        NULL
};

extern struct net_device *resolve_dev_impl(const struct in_addr *addr,
                                           int ifindex);

static inline struct net_device *resolve_dev(struct service_info *entry)
{
        return resolve_dev_impl(&entry->address, entry->if_index);
}

static int dummy_ctrlmsg_handler(struct ctrlmsg *cm)
{
        const char *type = ctrlmsg_str[cm->type];
	LOG_DBG("control message type %s\n", type);
        return 0;
}

static int ctrl_handle_add_service_msg(struct ctrlmsg *cm)
{
        struct ctrlmsg_service *cmr = (struct ctrlmsg_service *)cm;
        unsigned int num_res = CTRLMSG_SERVICE_NUM(cmr);
        /* TODO - flags, etc */
        unsigned int i, index = 0;
        int err = 0;

        LOG_DBG("adding %u services, msg size %u\n", 
                num_res, CTRLMSG_SERVICE_LEN(cmr));
        
        for (i = 0; i < num_res; i++) {
                struct net_device *dev = NULL;
                struct service_info *entry = &cmr->service[i];
                unsigned short prefix_bits = SERVICE_ID_MAX_PREFIX_BITS;

                dev = resolve_dev(entry);
                
                if (!dev)
                        continue;

                if (entry->srvid_prefix_bits > 0)
                        prefix_bits = entry->srvid_prefix_bits;
         
#if defined(ENABLE_DEBUG)
                {
                        char ipstr[18];
                        LOG_DBG("Adding service id: %s(%u) "
                                "@ address %s, priority %u, weight %u\n", 
                                service_id_to_str(&entry->srvid), 
                                prefix_bits, 
                                inet_ntop(AF_INET, &entry->address,
                                          ipstr, sizeof(ipstr)),
                                entry->priority, entry->weight);
                }
#endif
                err = service_add(&entry->srvid, 
                                  prefix_bits, 
                                  entry->srvid_flags, 
                                  entry->priority, 
                                  entry->weight,
                                  &entry->address, 
                                  sizeof(entry->address),
                                  dev, GFP_KERNEL);

                dev_put(dev);

                if (err > 0) {
                        if (index < i) {
                                /*copy it over */
                                memcpy(&cmr->service[index], 
                                       entry, sizeof(*entry));
                        }
                        index++;
                } else {
                        LOG_ERR("Error adding service %s: err=%d\n", 
                                service_id_to_str(&entry->srvid), err);
                }
        }

        cm->len = CTRLMSG_SERVICE_NUM_LEN(index);
        ctrl_sendmsg(cm, GFP_KERNEL);

        return 0;
}

static int ctrl_handle_del_service_msg(struct ctrlmsg *cm)
{
        struct ctrlmsg_service *cmr = (struct ctrlmsg_service *)cm;
        unsigned int num_res = CTRLMSG_SERVICE_NUM(cmr);
        unsigned char buffer[sizeof(struct ctrlmsg_service_info_stat) + 
                             sizeof(struct service_info_stat) * num_res];
        struct ctrlmsg_service_info_stat *cms = 
                (struct ctrlmsg_service_info_stat *)buffer;
        struct service_id null_service = { .s_sid = { 0 } };
        unsigned int i = 0;
        int index = 0;
        int err = 0;

#if defined(ENABLE_DEBUG)
        LOG_DBG("deleting %u services\n", num_res);
#endif

        for (i = 0; i < num_res; i++) {
                struct service_info *entry = &cmr->service[i];
                struct service_info_stat *stat = &cms->service[index];
                struct dest_stats dstat;
                struct service_entry *se;
                unsigned short prefix_bits = SERVICE_ID_MAX_PREFIX_BITS;

                /*
                  We might be trying to delete the "default" entry. In
                  that case
                */
                if (memcmp(&entry->srvid, &null_service, 
                           sizeof(null_service)) == 0 ||
                    entry->srvid_prefix_bits > 0)
                        prefix_bits = entry->srvid_prefix_bits;
                
                se = service_find_exact(&entry->srvid, 
                                        prefix_bits);

                if (!se) {
                        LOG_DBG("No match for serviceID %s:(%u)\n",
                                service_id_to_str(&entry->srvid),
                                prefix_bits);
                        continue;
                }

                memset(&dstat, 0, sizeof(dstat));
                
                err = service_entry_remove_dest(se, &entry->address, 
                                                sizeof(entry->address), 
                                                &dstat);

                if (err > 0) {
                        stat->duration_sec = dstat.duration_sec;
                        stat->duration_nsec = dstat.duration_nsec;
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
                                service_id_to_str(&entry->srvid), 
                                err);
                }

                service_entry_put(se);
        }

        cms->cmh.type = CTRLMSG_TYPE_SERVICE_STAT;
        cms->cmh.len = CTRLMSG_SERVICE_STAT_NUM_LEN(index);
        ctrl_sendmsg(&cms->cmh, GFP_KERNEL);

        return 0;
}

static int ctrl_handle_capabilities_msg(struct ctrlmsg *cm)
{
        struct ctrlmsg_capabilities *cmt = (struct ctrlmsg_capabilities*)cm;
        net_serval.sysctl_sal_forward = cmt->capabilities & SVSTK_TRANSIT;
        return 0;
}

static int ctrl_handle_mod_service_msg(struct ctrlmsg *cm)
{
        struct ctrlmsg_service *cmr = (struct ctrlmsg_service *)cm;
        unsigned int num_res = CTRLMSG_SERVICE_NUM(cmr);
        unsigned int i, index = 0;
        int err = 0;

        if (num_res < 2 || num_res % 2 != 0) {
                LOG_DBG("Not an even number of service infos\n");
                return 0;
        }

        LOG_DBG("modifying %u services\n", num_res / 2);

        for (i = 0; i < num_res; i += 2) {
                struct net_device *dev;
                struct service_info *entry_old = &cmr->service[i];
                struct service_info *entry_new = &cmr->service[i+1];
                unsigned short prefix_bits = SERVICE_ID_MAX_PREFIX_BITS;
                
                if (entry_old->srvid_prefix_bits > 0)
                        prefix_bits = entry_old->srvid_prefix_bits;

#if defined(ENABLE_DEBUG)
                {
                        char buf[18];
                        LOG_DBG("Modifying: %s flags(%i) bits(%i) %s\n", 
                                service_id_to_str(&entry_old->srvid), 
                                entry_old->srvid_flags, 
                                prefix_bits,
                                inet_ntop(AF_INET, &entry_old->address, 
                                          buf, 18));
                }
#endif
                dev = resolve_dev(entry_new);
                
                if (!dev)
                        continue;

                err = service_modify(&entry_old->srvid,
                                     prefix_bits,
                                     entry_old->srvid_flags, 
                                     entry_new->priority, 
                                     entry_new->weight, 
                                     &entry_old->address,
                                     sizeof(entry_old->address),
                                     &entry_new->address,
                                     sizeof(entry_new->address), 
                                     dev);
                if (err > 0) {
                        if (index < i) {
                                /*copy it over */
                                memcpy(&cmr->service[index], 
                                       entry_new, sizeof(*entry_new));
                        }
                        index++;
                } else {
                        LOG_ERR("Could not modify service %s: %i\n", 
                                service_id_to_str(&entry_old->srvid), 
                                err);
                }
        }

        cm->len = CTRLMSG_SERVICE_NUM_LEN(index);
        ctrl_sendmsg(cm, GFP_KERNEL);

        return 0;
}

static int ctrl_handle_get_service_msg(struct ctrlmsg *cm)
{
        struct ctrlmsg_service *cmg = (struct ctrlmsg_service *)cm;
        struct service_entry *se;
        struct service_resolution_iter iter;
        unsigned short prefix_bits = SERVICE_ID_MAX_PREFIX_BITS;
        struct dest *dst;
        int i = 0;

#if defined(ENABLE_DEBUG)
        LOG_DBG("getting service: %s\n",
                service_id_to_str(&cmg->service[0].srvid));
#endif
        if (cmg->service[0].srvid_prefix_bits > 0)
                prefix_bits = cmg->service[0].srvid_prefix_bits;

        se = service_find(&cmg->service[0].srvid, 
                          prefix_bits);

        if (se) {
                struct ctrlmsg_service *cres;
                size_t size = CTRLMSG_SERVICE_NUM_LEN(se->count);
                cres = kmalloc(size, GFP_KERNEL);

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
                        struct service_info *entry = &cres->service[i++];
                        
                        memcpy(&entry->srvid, 
                               &cmg->service[0].srvid, 
                               sizeof(cmg->service[0].srvid));
                        memcpy(&entry->address, 
                               dst->dst, dst->dstlen);
                        entry->srvid_prefix_bits = 
                                cmg->service[0].srvid_prefix_bits;
                        entry->srvid_flags = 
                                service_resolution_iter_get_flags(&iter);
                        entry->weight = dst->weight;
                        entry->priority = 
                                service_resolution_iter_get_priority(&iter);
                }

                service_resolution_iter_destroy(&iter);
                service_entry_put(se);

                ctrl_sendmsg(&cres->cmh, GFP_KERNEL);
                kfree(cres);
        } else {
                cmg->service[0].srvid_flags = SVSF_INVALID;
                ctrl_sendmsg(&cmg->cmh, GFP_KERNEL);
        }

        return 0;
}

static int ctrl_handle_service_stats_msg(struct ctrlmsg *cm)
{
        struct ctrlmsg_service_stat *cms = (struct ctrlmsg_service_stat *)cm;
        struct table_stats tstats;

        memset(&cms->stats, 0, sizeof(cms->stats));
        
        if (net_serval.sysctl_sal_forward) {
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

static int ctrl_handle_migrate_msg(struct ctrlmsg *cm)
{
        struct ctrlmsg_migrate *cmm = (struct ctrlmsg_migrate*)cm;
        struct net_device *old_dev, *new_dev;
        int ret = 0;
        
        new_dev = dev_get_by_name(&init_net, cmm->to_i);

        /* Check that migration destination is valid. */
        if (!new_dev) {
                LOG_ERR("No new interface %s\n", cmm->to_i);
                return -1;
        }

        switch (cmm->migrate_type) {
        case CTRL_MIG_IFACE:
                LOG_DBG("migrate iface %s to iface %s\n", 
                        cmm->from_i, cmm->to_i);
                old_dev = dev_get_by_name(&init_net, cmm->from_i);

                if (!old_dev) {
                        LOG_ERR("No old interface %s\n", cmm->from_i);
                        ret = -1;
                        break;  
                }
                serval_sock_migrate_iface(old_dev, new_dev);
                dev_put(old_dev);
                break;
        case CTRL_MIG_FLOW:
                LOG_DBG("migrate flow %s to iface %s\n", 
                        flow_id_to_str(&cmm->from_f), cmm->to_i);
                serval_sock_migrate_flow(&cmm->from_f, new_dev);
                break;
        case CTRL_MIG_SERVICE:
                LOG_DBG("migrate service to iface %s\n", cmm->to_i);
                serval_sock_migrate_service(&cmm->from_s, new_dev);
                break;
        }

        dev_put(new_dev);

        return ret;
}

ctrlmsg_handler_t handlers[] = {
        dummy_ctrlmsg_handler,
        dummy_ctrlmsg_handler,
        dummy_ctrlmsg_handler,
        ctrl_handle_add_service_msg,
        ctrl_handle_del_service_msg,
        ctrl_handle_mod_service_msg,
        ctrl_handle_get_service_msg,
        ctrl_handle_service_stats_msg,
        ctrl_handle_capabilities_msg,
        ctrl_handle_migrate_msg,
        dummy_ctrlmsg_handler,
};
