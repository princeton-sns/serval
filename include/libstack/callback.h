#ifndef _LIBSTACK_CALLBACK_H_
#define _LIBSTACK_CALLBACK_H_

#include <netinet/scaffold.h>

struct libstack_callbacks {
	void (*doregister)(struct service_id *);
};

int libstack_register_callbacks(struct libstack_callbacks *calls);
void libstack_unregister_callbacks(struct libstack_callbacks *calls);

#endif /* _LIBSTACK_CALLBACK_H_ */
