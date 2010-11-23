/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <libstack/ctrlmsg.h>
#include <libstack/callback.h>
#include "debug.h"

static struct libstack_callbacks *callbacks = NULL;

int ctrlmsg_handle(struct ctrlmsg *cm)
{
	int ret = 0;

	if (!callbacks) {
		LOG_ERR("No callbacks registered\n");
		return -1;
	}

	switch (cm->type) {
	case CTRLMSG_TYPE_REGISTER:
		callbacks->doregister((struct service_id *)cm->payload);
		break;
	default:
		LOG_ERR("no handler for msg type %u\n",
			cm->type);
	}

	return ret;
}


int libstack_register_callbacks(struct libstack_callbacks *calls)
{
	if (callbacks)
		return -1;

	callbacks = calls;
	
	return 0;
}

void libstack_unregister_callbacks(struct libstack_callbacks *calls)
{
	if (callbacks == calls)
		callbacks = NULL;
}
