/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * message_channel.h
 *
 *  Created on: Feb 11, 2011
 *      Author: daveds
 */

#ifndef MESSAGE_CHANNEL_BASE_H_
#define MESSAGE_CHANNEL_BASE_H_

#include "message_channel.h"

struct sv_message_channel_base {
    message_channel channel;
    int sock;
    atomic_t running;
    task_handle_t recv_task;
    /* receive buffer */
    char *buffer;
    int buffer_len;
    message_channel_callback callback;
};

int base_message_channel_initialize(message_channel * channel);
int base_message_channel_finalize(message_channel * channel);
void base_message_channel_stop(message_channel * channel);
void base_message_channel_start(message_channel * channel);
int base_message_channel_register_callback(message_channel * channel,
					   message_channel_callback * cb);
int base_message_channel_unregister_callback(message_channel * channel,
					     message_channel_callback * cb);
int base_message_channel_get_callback_count(message_channel * channel);
#endif				/* MESSAGE_CHANNEL_BASE_H_ */
