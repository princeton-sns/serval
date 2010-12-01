/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _EVENT_H
#define _EVENT_H

#include <sys/types.h>

struct event_handler {
	char *name;
	int (*init)(struct event_handler *);
	int (*getfd)(struct event_handler *);
	void (*cleanup)(struct event_handler *);
	int (*handle_event)(struct event_handler *);
	int (*send)(struct event_handler *, const void *data, size_t datalen);
	void *private;		
};

void event_register_handler(struct event_handler *);
void event_unregister_handler(struct event_handler *);
int event_sendmsg(const void *data, size_t datalen);

#endif /* _EVENT_H */
