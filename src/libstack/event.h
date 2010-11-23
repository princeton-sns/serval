/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _EVENT_H
#define _EVENT_H

struct event_handler {
	char *name;
	int (*init)(struct event_handler *);
	int (*getfd)(struct event_handler *);
	void (*cleanup)(struct event_handler *);
	int (*handle_event)(struct event_handler *);
	void *private;		
};

void event_register_handler(struct event_handler *);
void event_unregister_handler(struct event_handler *);

#endif /* _EVENT_H */
