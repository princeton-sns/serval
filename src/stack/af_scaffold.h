/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _AF_SCAFFOLD_H
#define _AF_SCAFFOLD_H

#if defined(__KERNEL__)

#include <linux/socket.h>
#include <linux/mutex.h>
#include <net/sock.h>
#include <linux/wait.h>
#include <linux/skbuff.h>

#else

int scaffold_init(void);
void scaffold_fini(void);

#endif /* __KERNEL__ */

#include <netinet/scaffold.h>

#endif /* AF_SCAFFOLD_H */
