#ifndef _LIBSTACK_H
#define _LIBSTACK_H

#include "callback.h"
#include "ctrlmsg.h"

int libstack_configure_interface(const char *ifname, unsigned short flags);

int libstack_init(void);
void libstack_fini(void);

#endif /* LIBSTACK_H */
