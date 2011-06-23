/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _LIBSTACK_CALLBACK_H_
#define _LIBSTACK_CALLBACK_H_

#include <netinet/serval.h>

struct libstack_callbacks {
	void (*srvregister)(struct service_id *);
};

int libstack_register_callbacks(struct libstack_callbacks *calls);
void libstack_unregister_callbacks(struct libstack_callbacks *calls);

#endif /* _LIBSTACK_CALLBACK_H_ */
