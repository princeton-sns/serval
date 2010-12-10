/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <libstack/ctrlmsg.h>
#include <libstack/callback.h>
#include "debug.h"

struct libstack_callbacks *callbacks = NULL;

static unsigned int ctrlmsg_sizes[] = {
        CTRLMSG_SIZE,
        CTRLMSG_SIZE,
        CTRLMSG_REGISTER_SIZE,
        CTRLMSG_IFACE_CONF_SIZE,
        CTRLMSG_SERVICE_SIZE,
        CTRLMSG_UNREGISTER_SIZE
};

static inline int ctrlmsg_check(struct ctrlmsg *cm, unsigned int len)
{
        if (cm->type >= CTRLMSG_TYPE_UNKNOWN) {
                LOG_ERR("type error, type=%u\n",
                        cm->type);
                return -1;
        } else if (len != cm->len) {
                LOG_ERR("rcv len mismatch was=%u rcvlen=%u\n",
                        len, cm->len);
                return -1;    
        } else if (len < ctrlmsg_sizes[cm->type]) {
                LOG_ERR("type len mismatch len=%u typesize=%u\n",
                        len, ctrlmsg_sizes[cm->type]);
                return -1;                
        }
        return 0;
}

int ctrlmsg_handle(struct ctrlmsg *cm, unsigned int len)
{
	int ret = 0;

        if (ctrlmsg_check(cm, len) != 0)
                return -1;

	if (!callbacks) {
		LOG_ERR("No callbacks registered\n");
		return -1;
	}

        LOG_DBG("type=%u len=%u\n", cm->type, len);

	switch (cm->type) {
	case CTRLMSG_TYPE_REGISTER:
                if (callbacks->srvregister) {
                        struct ctrlmsg_register *cmr = 
                                (struct ctrlmsg_register *)cm;
                        callbacks->srvregister(&cmr->srvid);
                }
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
