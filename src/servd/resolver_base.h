/*
 * resolver_base.h
 *
 *  Created on: Feb 18, 2011
 *      Author: daveds
 */

#ifndef RESOLVER_BASE_H_
#define RESOLVER_BASE_H_

#include <glib.h>
#include "serval/atomic.h"
#include "resolver.h"

struct sv_base_service_resolver {
    service_resolver resolver;
    atomic_t ref_count;
    GArray* addresses;
    GPtrArray* service_descs;
    GArray* peer_status_callbacks;
};

void base_resolver_set_address(service_resolver* resolver, struct sockaddr* saddr, size_t len);
int base_resolver_initialize(service_resolver* resolver);
int base_resolver_finalize(service_resolver* resolver);
void base_resolver_incref(service_resolver* resolver);
void init_base_resolver(struct sv_base_service_resolver *base);
void base_set_capabilities (service_resolver* resolver, uint32_t capabilities);
void notify_peer_status_callbacks(service_resolver* resolver, service_resolver* peer, enum resolver_state status);
#endif /* RESOLVER_BASE_H_ */
