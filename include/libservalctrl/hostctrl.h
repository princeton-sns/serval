/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Interface and API for writing end-host control programs for the
 * Serval stack, running on top of message channels.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#ifndef _HOSTCTRL_H_
#define _HOSTCTRL_H_

#include <netinet/serval.h>
#include <serval/ctrlmsg.h>
#include "message_channel.h"

struct hostctrl;

/*
  Host control callbacks.
*/
struct hostctrl_callback {
    int (*service_registration)(struct hostctrl *hc,
                                const struct service_id *srvid,
                                unsigned short flags,
                                unsigned short prefix,
                                const struct in_addr *ip,
                                const struct in_addr *old_ip);
    int (*service_unregistration)(struct hostctrl *hc,
                                  const struct service_id *srvid,
                                  unsigned short flags,
                                  unsigned short prefix,
                                  const struct in_addr *ip);
    int (*service_stat_update)(struct hostctrl *hc,
                               unsigned int xid,
                               int retval,
                               const struct service_stat *stat,
                               unsigned int num_stat);
    int (*service_get_result)(struct hostctrl *hc,
                              unsigned int xid,
                              int retval,
                              const struct service_info *si,
                              unsigned int num);
    int (*service_add_result)(struct hostctrl *hc,
                              unsigned int xid,
                              int retval,
                              const struct service_info *si,
                              unsigned int num);
    int (*service_mod_result)(struct hostctrl *hc,
                              unsigned int xid,
                              int retval,
                              const struct service_info *si,
                              unsigned int num);
    int (*service_remove_result)(struct hostctrl *hc,
                                 unsigned int xid,
                                 int retval,
                                 const struct service_info_stat *sis,
                                 unsigned int num);
    int (*service_delay_notification)(struct hostctrl *hc,
                                      unsigned int xid,
                                      unsigned int pkt_id,
                                      struct service_id *service);
    int (*start)(struct hostctrl *hc); /* Called one time, when thread starts */
    void (*stop)(struct hostctrl *hc); /* Called when thread stops */
};

struct hostctrl_ops;

typedef struct hostctrl {
	struct message_channel *mc;
    void *context;
    unsigned int xid;
	const struct hostctrl_ops *ops;
	const struct hostctrl_callback *cbs;
	struct message_channel_callback mccb;
} hostctrl_t;

enum hostctrl_flags {
    HCF_NONE   = 0,
    HCF_ROUTER = 1 << 0,
    HCF_START  = 1 << 1,
};

struct hostctrl *
hostctrl_remote_create_specific(const struct hostctrl_callback *cbs,
                                void *context, 
                                struct sockaddr *local, socklen_t local_len ,
                                struct sockaddr *peer, socklen_t peer_len, 
                                unsigned short flags);
struct hostctrl *hostctrl_remote_create(const struct hostctrl_callback *cbs,
                                        void *context, 
                                        unsigned short flags);
struct hostctrl *hostctrl_local_create(const struct hostctrl_callback *cbs,
                                       void *context, 
                                       unsigned short flags);
void hostctrl_free(struct hostctrl *hc);
int hostctrl_start(struct hostctrl *hc);

unsigned int hostctrl_get_xid(struct hostctrl *hc);
int hostctrl_interface_migrate(struct hostctrl *hc, 
                               const char *from, const char *to);
int hostctrl_flow_migrate(struct hostctrl *hc, struct flow_id *flow,
                          const char *to_iface);
int hostctrl_service_migrate(struct hostctrl *hc, 
                             struct service_id *srvid,
                             const char *to_iface);
int hostctrl_service_register(struct hostctrl *hc, 
                              const struct service_id *srvid, 
                              unsigned short prefix_bits,
                              const struct in_addr *old_ip);
int hostctrl_service_unregister(struct hostctrl *hc, 
                                const struct service_id *srvid, 
                                unsigned short prefix_bits);
int hostctrl_service_add(struct hostctrl *hc, 
                         enum service_rule_type type,
                         const struct service_id *srvid, 
                         unsigned short prefix_bits,
                         unsigned int priority,
                         unsigned int weight,
                         const struct in_addr *ipaddr);
int hostctrl_service_remove(struct hostctrl *hc,
                            enum service_rule_type type,
                            const struct service_id *srvid, 
                            unsigned short prefix_bits,
                            const struct in_addr *ipaddr);
int hostctrl_service_get(struct hostctrl *hc,
                         const struct service_id *srvid,
                         unsigned short prefix_bits,
                         const struct in_addr *ipaddr);
int hostctrl_service_modify(struct hostctrl *hc,
                            enum service_rule_type type,
                            const struct service_id *srvid, 
                            unsigned short prefix_bits,
                            unsigned int priority,
                            unsigned int weight,
                            const struct in_addr *old_ip,
                            const struct in_addr *new_ip);
int hostctrl_services_add(struct hostctrl *hc,
                          const struct service_info *si,
                          unsigned int num_si);
int hostctrl_services_remove(struct hostctrl *hc,
                             const struct service_info *si,
                             unsigned int num_si);

int hostctrl_service_query(struct hostctrl *hc,
                           struct service_id *srvid,
                           unsigned short flags,
                           unsigned short prefix,
                           struct service_info_stat **si);

int hostctrl_set_capabilities(struct hostctrl *hc,
                              uint32_t capabilities);

int hostctrl_get_local_addr(struct hostctrl *hc, struct sockaddr *addr, 
                            socklen_t *addrlen);

int hostctrl_get_peer_addr(struct hostctrl *hc, struct sockaddr *addr, 
                           socklen_t *addrlen);

int hostctrl_set_delay_verdict(struct hostctrl *hc,
                               unsigned int pkt_id,
                               enum delay_verdict verdict);
#endif /* _HOSTCTRL_H_ */
