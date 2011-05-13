/*
 * message_channel.h
 *
 *  Created on: Feb 11, 2011
 *      Author: daveds
 */

#ifndef MESSAGE_CHANNEL_BASE_H_
#define MESSAGE_CHANNEL_BASE_H_

#include "message_channel.h"

struct base_message_channel {
    int sock;
    atomic_t running;
    task_handle_t recv_task;
    /* receive buffer */
    char* buffer;
    int buffer_len;
    message_channel_callback callback;
};

int base_message_channel_initialize(void* target);
int base_message_channel_finalize(void* target);
void base_message_channel_stop(void* target);
void base_message_channel_start(void* target);
int base_message_channel_register_callback(void* target, message_channel_callback* cb);
int base_message_channel_unregister_callback(void* target, message_channel_callback* cb);
int base_message_channel_get_callback_count(void* target);
#endif /* MESSAGE_CHANNEL_BASE_H_ */
