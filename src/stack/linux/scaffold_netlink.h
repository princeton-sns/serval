/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SCAFFOLD_NETLINK_H
#define _SCAFFOLD_NETLINK_H

#define NETLINK_SCAFFOLD 17

int scaffold_netlink_init(void);
void scaffold_netlink_fini(void);
int scaffold_netlink_send(int type, void *data, unsigned int len, int mask);

#endif /* _SCAFFOLD_NETLINK_H */
