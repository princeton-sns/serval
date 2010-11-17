/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SCAFFOLD_NETLINK_H
#define _SCAFFOLD_NETLINK_H

#define NETLINK_SCAFFOLD 17

#if defined(__KERNEL__)
int scaffold_netlink_init(void);
void scaffold_netlink_fini(void);
#endif

#endif /* _SCAFFOLD_NETLINK_H */
