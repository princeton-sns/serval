/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _LIBSTACK_H
#define _LIBSTACK_H

#include <netinet/serval.h>
#include "callback.h"
#include "ctrlmsg.h"

int libstack_configure_interface(const char *ifname, 
                                 const struct net_addr *ipaddr,
				 unsigned short flags);

int libstack_add_service(const struct service_id *srvid, 
                         unsigned int prefix_bits,
                         const struct in_addr *ipaddr);

int libstack_del_service(const struct service_id *srvid, 
                         unsigned int prefix_bits,
                         const struct in_addr *ipaddr);
int libstack_init(void);
void libstack_fini(void);

#endif /* LIBSTACK_H */
