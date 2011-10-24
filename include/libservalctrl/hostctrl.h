/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
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
        int (*service_registration)(void *context,
                                    const struct service_id *srvid,
                                    unsigned short flags,
                                    unsigned short prefix,
                                    const struct in_addr *ip);
        int (*service_unregistration)(void *context,
                                      const struct service_id *srvid,
                                      unsigned short flags,
                                      unsigned short prefix,
                                      const struct in_addr *ip);
        int (*service_stat_update)(void *context,
                                   struct service_info_stat *stat,
                                   unsigned int num_stat);
        int (*service_resolve)(void *context,
                               const struct service_id *srvid,
                               unsigned short flags,
                               unsigned short prefix);
};

struct hostctrl_ops;

typedef struct hostctrl {
	struct message_channel *mc;
        void *context;
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

int hostctrl_interface_migrate(struct hostctrl *hc, 
                               const char *from, const char *to);
int hostctrl_flow_migrate(struct hostctrl *hc, struct flow_id *flow,
                          const char *to_iface);
int hostctrl_service_migrate(struct hostctrl *hc, 
                             struct service_id *srvid,
                             const char *to_iface);
int hostctrl_service_register(struct hostctrl *hc, 
                              const struct service_id *srvid, 
                              unsigned short prefix_bits);
int hostctrl_service_unregister(struct hostctrl *hc, 
                                const struct service_id *srvid, 
                                unsigned short prefix_bits);
int hostctrl_service_add(struct hostctrl *hc, 
                         const struct service_id *srvid, 
                         unsigned short prefix_bits,
                         const struct in_addr *ipaddr);
int hostctrl_service_remove(struct hostctrl *hc,
                            const struct service_id *srvid, 
                            unsigned short prefix_bits,
                            const struct in_addr *ipaddr);
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

#endif /* _HOSTCTRL_H_ */
