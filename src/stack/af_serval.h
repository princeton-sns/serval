/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _AF_SERVAL_H
#define _AF_SERVAL_H

#include <serval/platform.h>

int __init serval_init(void);
void __exit serval_fini(void);

struct ctl_table_header;

/* Control variables for Serval. */
struct netns_serval {
	int sysctl_sal_forward;
	int sysctl_udp_encap;
        int sysctl_udp_encap_client_port;
        int sysctl_udp_encap_server_port;
	struct ctl_table_header *ctl;
};

extern struct netns_serval net_serval;

#endif /* AF_SERVAL_H */
