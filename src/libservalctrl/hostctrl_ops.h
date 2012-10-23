/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef _HOSTCTRL_OPS_H_
#define _HOSTCTRL_OPS_H_

/*
  Host control operations.
*/
struct hostctrl_ops {
	int (*interface_migrate)(struct hostctrl *hc, 
                             const char *from, const char *to);
	int (*flow_migrate)(struct hostctrl *hc, struct flow_id *flow,
                        const char *to_iface);
	int (*service_migrate)(struct hostctrl *hc, 
                           struct service_id *srvid,
                           const char *to_iface);
    int (*service_register)(struct hostctrl *hc, 
                            const struct service_id *srvid, 
                            unsigned short prefix_bits,
                            const struct in_addr *old_ip);
	int (*service_unregister)(struct hostctrl *hc,
                              const struct service_id *srvid, 
                              unsigned short prefix_bits);
    int (*service_add)(struct hostctrl *hc,
                       enum service_rule_type type,
                       const struct service_id *srvid, 
                       unsigned short prefix_bits,
                       unsigned int priority,
                       unsigned int weight,
                       const struct in_addr *ipaddr);
    int (*service_remove)(struct hostctrl *hc, 
                          enum service_rule_type type,
                          const struct service_id *srvid, 
                          unsigned short prefix_bits,
                          const struct in_addr *ipaddr);
    int (*service_modify)(struct hostctrl *hc,
                          enum service_rule_type type,
                          const struct service_id *srvid, 
                          unsigned short prefix_bits,
                          unsigned int priority,
                          unsigned int weight,
                          const struct in_addr *old_ip,
                          const struct in_addr *new_ip);
    int (*service_get)(struct hostctrl *hc, 
                       const struct service_id *srvid, 
                       unsigned short prefix_bits,
                       const struct in_addr *ipaddr);
    int (*services_add)(struct hostctrl *hc,
                        const struct service_info *si,
                        unsigned int num_si);
    int (*services_remove)(struct hostctrl *hc,
                           const struct service_info *si,
                           unsigned int num_si);
    int (*services_query)(struct hostctrl *hc,
                          const struct service_info *si,
                          unsigned int num_si);
    int (*service_delay_verdict)(struct hostctrl *hc,
                                 unsigned int pkt_id,
                                 enum delay_verdict verdict);
    int (*ctrlmsg_recv)(struct hostctrl *hc, struct ctrlmsg *cm,
                        struct sockaddr *from, socklen_t from_len);
};

int handle_service_change(struct hostctrl *hc, 
                          struct ctrlmsg_register *cmr,
                          const struct in_addr *ip,
                          int (*const callback)(struct hostctrl *hc,
                                                const struct service_id *srvid,
                                                unsigned short flags,
                                                unsigned short prefix,
                                                const struct in_addr *ip));
#endif /* _HOSTCTRL_OPS_H_ */
