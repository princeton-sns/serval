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
    /**
     * @brief Service registration callback.
     * 
     * This callback will be called in case a new service becomes
     * available locally on the host or at a remote host.
     */
    int (*service_registration)(struct hostctrl *hc,
                                const struct service_id *srvid,
                                unsigned short flags,
                                unsigned short prefix,
                                const struct in_addr *ip,
                                const struct in_addr *old_ip);
    /**
     * @brief Service unregistration callback.
     * 
     * This callback will be called in case a previously registered
     * service is no longer available locally on the host or at a
     * remote host.
     */
    int (*service_unregistration)(struct hostctrl *hc,
                                  const struct service_id *srvid,
                                  unsigned short flags,
                                  unsigned short prefix,
                                  const struct in_addr *ip);
    /**
     * @brief Service statistics update.
     * 
     * This callback will be called in response to a service
     * statistics request.
     */
    int (*service_stat_update)(struct hostctrl *hc,
                               unsigned int xid,
                               int retval,
                               const struct service_stat *stat,
                               unsigned int num_stat);
    /**
     * @brief Service query response callback.
     * 
     * This callback will be called in response to a service GET
     * request that asks for the available services on localhost or a
     * remote host.
     */
    int (*service_get_result)(struct hostctrl *hc,
                              unsigned int xid,
                              int retval,
                              const struct service_info *si,
                              unsigned int num);
    /**
     * @brief Service addition result callback.
     * 
     * This callback will be called in response to a service ADD
     * request that adds a new service entry on localhost or a remote
     * host.
     */
    int (*service_add_result)(struct hostctrl *hc,
                              unsigned int xid,
                              int retval,
                              const struct service_info *si,
                              unsigned int num);
    /**
     * @brief Service modification result callback.
     * 
     * This callback will be called in response to a service MOD
     * request that modifies a service entry on localhost or a remote
     * host.
     */
    int (*service_mod_result)(struct hostctrl *hc,
                              unsigned int xid,
                              int retval,
                              const struct service_info *si,
                              unsigned int num);
    /**
     * @brief Service modification result callback.
     * 
     * This callback will be called in response to a service REMOVE
     * request that removes a service entry on localhost or a remote
     * host.
     */
    int (*service_remove_result)(struct hostctrl *hc,
                                 unsigned int xid,
                                 int retval,
                                 const struct service_info_stat *sis,
                                 unsigned int num);

    /**
     * @brief Service modification result callback.
     * 
     * This callback will be called in response to a service flow
     * statistics update request on localhost.
     */
    int (*flow_stat_update)(struct hostctrl *hc,
                            unsigned int xid,
                            int retval,
                            struct ctrlmsg_stats_response *csr);

    /**
     * @brief Service delay notification.
     * 
     * This callback will be called for any packet that is queued in
     * the stack because it matches a DELAY rule in the local host's
     * service table. It is expected that the recipient of this
     * notification will eventually notify the local stack of a
     * verdict for the packet.
     *
     * @param hc The host control handle associated with this notification.
     * @param xid The transaction ID for this notification.
     * @param pkt_id An unique ID for the packet that is queued in the
     * kernel. This ID is used to specify the packet's verdict.
     * @param service The serviceID that the packet matched.
     */
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

/**
 * @brief Create handle for remote service operations.
 * 
 * This function will create a host control channel handle for
 * performing operations against remote hosts.
 *
 * @param cbs The callbacks to use for handling events
 * @param context A context to be passed to the callback functions.
 * @param local The local address and family to use for the channel.
 * @param local_len The length of the @p local address.
 * @param peer The remote address to which the channel should be opened.
 * @param peer_len The length of the @p peer address.
 * @param flags Flags indicating the following: HFC_NONE for no flags, 
 * HFC_ROUTER if this is a service router (and not service endpoint), 
 * HFC_START if the channel should start its event loop.
 * @return A new host control handle.
 *
 */
struct hostctrl *
hostctrl_remote_create_specific(const struct hostctrl_callback *cbs,
                                void *context, 
                                struct sockaddr *local, socklen_t local_len ,
                                struct sockaddr *peer, socklen_t peer_len, 
                                unsigned short flags);
/**
 * @brief Create handle for remote service operations against the
 * "local network" service router.
 *
 * This function creates a remote host control channel to the
 * "default" service router in the local network (by using a
 * predefined serviceID for local service routers). The functionality
 * is otherwise equivalent to hostctrl_remote_create_specific.
 *
 * @param cbs The callbacks to use for handling events.
 * @param context A context to be passed to the callback functions.
 * @param flags Flags indicating the following: HFC_NONE for no flags, 
 * HFC_ROUTER if this is a service router (and not service endpoint), 
 * HFC_START if the channel should start its event loop.
 * @return A new host control handle.
 */
struct hostctrl *hostctrl_remote_create(const struct hostctrl_callback *cbs,
                                        void *context, 
                                        unsigned short flags);
/**
 * @brief Create handle for localhost (stack) service operations.
 *
 * This function creates a host control channel to the localhost
 * network stack.
 *
 * @param cbs The callbacks to use for handling events.
 * @param context A context to be passed to the callback functions.
 * @param flags Flags indicating the following: HFC_NONE for no flags, 
 * HFC_ROUTER if this is a service router (and not service endpoint),
 * HFC_START if the channel should start its event loop.
 * @return A new host control handle.
 */
struct hostctrl *hostctrl_local_create(const struct hostctrl_callback *cbs,
                                       void *context, 
                                       unsigned short flags);

/**
 * @brief Free a handle's resources after it is no longer needed.
 * 
 * This function frees resources associated with a host control handle
 * and should always be called when the handle is no longer needed. It
 * will also close any connections to other hosts or service routers.
 *
 * @param hc The host control handle to free.
 */
void hostctrl_free(struct hostctrl *hc);

/**
 * @brief Start event processing for a host control handle.
 * 
 * This function starts an event loop for the given host control
 * handle that will process any channel events.
 *
 * @param hc A host control handle.
 * @return Zero on success or negative (error number) on failure.
 */
int hostctrl_start(struct hostctrl *hc);

/**
 * @brief Return the most recent transaction ID on a channel.
 *
 * @param hc A host control handle.
 * @return The transaction ID.
 */
unsigned int hostctrl_get_xid(struct hostctrl *hc);

/**
 * @brief Migrate all flows on one interface to another.
 * 
 * @param hc A host control handle.
 * @param from The name of the interface to migrate flows from.
 * @param to The name of the interface to migrate flows to.

 * @return Zero on success or -1 on failure. Note, that success only
 * indicates that the message was successfully sent, not that the
 * operation was successful.
 */
int hostctrl_interface_migrate(struct hostctrl *hc, 
                               const char *from, const char *to);

/**
 * @brief Migrate a flow from one interface to another.
 * 
 * @param hc A host control handle.
 * @param flow The flowID number of the flow to migrate.
 * @param to_iface The name of the interface to migrate the flow to.

 * @return Zero on success or -1 on failure. Note, that success only
 * indicates that the message was successfully sent, not that the
 * operation was successful.
 */
int hostctrl_flow_migrate(struct hostctrl *hc, struct flow_id *flow,
                          const char *to_iface);

/**
 * @brief Migrate all flows associated with a service to another
 * interface.
 * 
 * @param hc A host control handle.
 * @param srvid The serviceID assoicated with the flows to migrate.
 * @param to_iface The name of the interface to migrate the flows to.

 * @return Zero on success or -1 on failure. Note, that success only
 * indicates that the message was successfully sent, not that the
 * operation itself was successful.
 */
int hostctrl_service_migrate(struct hostctrl *hc, 
                             struct service_id *srvid,
                             const char *to_iface);

/**
 * @brief Query flows for statistics.
 *
 * Request statistics for specific flows. The stats will be passed in
 * a registered flow_stats_update callback.
 *
 * @param hc A host control handle.
 * @param flowids An array of flowIDs to get stats for.
 * @param flows The number of flowIDs in the @p flowids array.
 * @return Zero on success or -1 on failure. Note, that success only
 * indicates that the message was successfully sent, not that the
 * operation itself was successful. Additional error information may be 
 * passed in the associated callback.
 */
int hostctrl_flow_stats_query(struct hostctrl *hc, struct flow_id *flowids,
                              int flows);

/**
 * @brief Register a new service entry with a remote service router.
 *
 * This function will register a new service with a service router. It
 * is typically called in response to a service register event in the
 * local network stack (a local service started to run) and will
 * forward the event to a remote service router (e.g., in the local
 * network). The IP address that will be registered with the service
 * is the default local address used to transmit the registration
 * message.
 *
 * @param hc A host control handle.
 * @param srvid The serviceID to register.
 * @param prefix_bits Indicates whether a prefix or a full serviceID
 * should be registered. Zero indicates a full serviceID (all bits).
 * @param old_ip The previously registered IP address (in case of a
 * registration update), or NULL.
 * @return Zero on success or -1 on failure. Note, that success only
 * indicates that the message was successfully sent, not that the
 * operation itself was successful.
 */
int hostctrl_service_register(struct hostctrl *hc, 
                              const struct service_id *srvid, 
                              unsigned short prefix_bits,
                              const struct in_addr *old_ip);

/**
 * @brief Unregister a previously registered service entry at a remote
 * service router.
 *
 * This function will unregister a service entry at a remote service
 * router. It is typically called in response to a service unregister
 * event in the local network stack (a service stopped running) and
 * will forward the event to a remote service router (e.g., in the
 * local network).
 *
 * @param hc A host control handle.
 * @param srvid The serviceID to unregister.
 * @param prefix_bits The prefix of the service entry to
 * unregister. Zero for all bits.
 * @return Zero on success or -1 on failure. Note, that success only
 * indicates that the message was successfully sent, not that the
 * operation itself was successful. 
 */
int hostctrl_service_unregister(struct hostctrl *hc, 
                                const struct service_id *srvid, 
                                unsigned short prefix_bits);

/**
 * @brief Add a service entry to the local service table or a remote
 * service router.
 *
 * This function will add a service entry in the local service table
 * or a remote service router. While the register function is called
 * in response to a network stack event, this function can be used to
 * add any type of service entries (except DEMUX ones).
 *
 * @param hc A host control handle.
 * @param type The service entry type (SERVICE_RULE_FORWARD,
 * SERVICE_RULE_DELAY, SERVICE_RULE_DROP).
 * @param srvid The serviceID to add.
 * @param prefix_bits The prefix of the serviceID to add. Zero for all
 * bits.
 * @param priority The priority of the the entry.
 * @param weight The weight of the entry.
 * @param ipaddr The address to associate with a FORWARD entry
 * (otherwise NULL).
 * @return Zero on success or -1 on failure. Note, that success only
 * indicates that the message was successfully sent, not that the
 * operation itself was successful. Additional error information may be 
 * passed in the associated callback.
 */
int hostctrl_service_add(struct hostctrl *hc, 
                         enum service_rule_type type,
                         const struct service_id *srvid, 
                         unsigned short prefix_bits,
                         unsigned int priority,
                         unsigned int weight,
                         const struct in_addr *ipaddr);

/**
 * @brief Remove a service entry from the local service table or a
 * remote service router.
 *
 * This function will remove a service entry in the local service
 * table or on a remote service router. While the unregister function
 * is called in response to a network stack event, this function can
 * be used to remove any type of service entries (except DEMUX ones).
 *
 * @param hc A host control handle.
 * @param type The service entry type (SERVICE_RULE_FORWARD,
 * SERVICE_RULE_DELAY, SERVICE_RULE_DROP).
 * @param srvid The serviceID to remove.
 * @param prefix_bits The prefix of the serviceID to remove. Zero for
 * all bits.
 * @param ipaddr The address associated with a FORWARD entry
 * (otherwise NULL).
 * @return Zero on success or -1 on failure. Note, that success only
 * indicates that the message was successfully sent, not that the
 * operation itself was successful. Additional error information may be 
 * passed in the associated callback.
 */
int hostctrl_service_remove(struct hostctrl *hc,
                            enum service_rule_type type,
                            const struct service_id *srvid, 
                            unsigned short prefix_bits,
                            const struct in_addr *ipaddr);
/**
 * @brief Get service entry information from the local service table
 * or a remote service router.
 *
 * This function will request service entry information from the local
 * service table or a remote service router. 
 *
 * @param hc A host control handle.
 * @param srvid The serviceID to remove.
 * @param prefix_bits The prefix of the serviceID to remove. Zero for
 * all bits.
 * @param ipaddr The address associated with the entry
 * (NULL if not applicable).
 * @return Zero on success or -1 on failure. Note, that success only
 * indicates that the message was successfully sent, not that the
 * operation itself was successful. Additional error information may be 
 * passed in the associated callback.
 */
int hostctrl_service_get(struct hostctrl *hc,
                         const struct service_id *srvid,
                         unsigned short prefix_bits,
                         const struct in_addr *ipaddr);

/**
 * @brief Modify a service entry in the local service table or on a
 * remote service router.
 *
 * This function will modify a service entry in the local service
 * table or on a remote service router. 

 * @param hc A host control handle.
 * @param type The service entry type (SERVICE_RULE_FORWARD,
 * SERVICE_RULE_DELAY, SERVICE_RULE_DROP).
 * @param srvid The serviceID to modify.
 * @param prefix_bits The prefix of the serviceID to modify. Zero for
 * all bits.
 * @param priority The new priority of the the entry.
 * @param weight The new weight of the entry.
 * @param old_ip The old (existing) address associated with a FORWARD entry
 * (otherwise NULL).
 * @param new_ip The new IP address to associate with this entry (NULL
 * if now applicable).
 * @return Zero on success or -1 on failure. Note, that success only
 * indicates that the message was successfully sent, not that the
 * operation itself was successful. Additional error information may be 
 * passed in the associated callback.
 */
int hostctrl_service_modify(struct hostctrl *hc,
                            enum service_rule_type type,
                            const struct service_id *srvid, 
                            unsigned short prefix_bits,
                            unsigned int priority,
                            unsigned int weight,
                            const struct in_addr *old_ip,
                            const struct in_addr *new_ip);

/**
 * @brief Add multiple service to a local or remote service table.
 *
 */
int hostctrl_services_add(struct hostctrl *hc,
                          const struct service_info *si,
                          unsigned int num_si);

/**
 * @brief Remove multiple service to a local or remote service table.
 *
 */
int hostctrl_services_remove(struct hostctrl *hc,
                             const struct service_info *si,
                             unsigned int num_si);

/**
 * @brief Query a service for statistics.
 *
 */
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

/**
 * @brief Set the verdict of a packet that is queued in the network
 * stack due to matching a DELAY rule.
 *
 * This function should be called in response to a delay notification
 * that indicates that a packet has been delayed (queued) in the
 * network stack. 
 * 
 * @param hc A host control handle.
 * @param pkt_id The ID of the packet to set the verdict for. This is
 * the ID previously passed in a delay notification event.
 * @param verdict The packet's verdict (DELAY_RELEASE or DELAY_DROP).
 * @return Zero on success or -1 on failure. Note, that success only
 * indicates that the message was successfully sent, not that the
 * operation itself was successful.
 */
int hostctrl_set_delay_verdict(struct hostctrl *hc,
                               unsigned int pkt_id,
                               enum delay_verdict verdict);
#endif /* _HOSTCTRL_H_ */
