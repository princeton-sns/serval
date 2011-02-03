/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _LIBSTACK_H
#define _LIBSTACK_H

#include <netinet/serval.h>
#include "callback.h"
#include "ctrlmsg.h"

int libstack_configure_interface(const char *ifname, 
                                 const struct net_addr *ipaddr,
				 unsigned short flags);

int libstack_set_service(struct service_id *srvid, const char *ifname);
int libstack_init(void);
void libstack_fini(void);

#endif /* LIBSTACK_H */
