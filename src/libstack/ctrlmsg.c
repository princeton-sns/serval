/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <libstack/ctrlmsg.h>
#include <libstack/callback.h>
#include "debug.h"

extern struct libstack_callbacks *callbacks;

int ctrlmsg_handle(struct ctrlmsg *cm)
{
	int ret = 0;

	if (!callbacks) {
		LOG_ERR("No callbacks registered\n");
		return -1;
	}

	switch (cm->type) {
	case CTRLMSG_TYPE_REGISTER:
		callbacks->srvregister((struct service_id *)cm->payload);
		break;
	default:
		LOG_ERR("no handler for msg type %u\n",
			cm->type);
	}

	return ret;
}


int ctrlmsg_send(struct ctrlmsg *cm)
{
        return 0;
}
