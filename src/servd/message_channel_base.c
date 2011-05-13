/*
 * base_message_channel.c
 *
 *  Created on: Apr 14, 2011
 *      Author: daveds
 */

#include <assert.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include "serval/platform.h"
#include "serval/atomic.h"
#include "debug.h"
#include "service_util.h"
#include "task.h"
#include "message_channel_base.h"

int base_message_channel_initialize(void* target) {
    assert(target);
    struct base_message_channel* channel = (struct base_message_channel*) target;
    channel->buffer = (char*) malloc(channel->buffer_len);
    bzero(channel->buffer, channel->buffer_len);
    return 0;
}

int base_message_channel_finalize(void* target) {
    assert(target);
    struct base_message_channel* channel = (struct base_message_channel*) target;

    if(atomic_read(&channel->running)) {
        base_message_channel_stop(channel);
    }

    if(channel->buffer) {
        free(channel->buffer);
        channel->buffer = NULL;
    }

    if(channel->sock > 0) {
        close(channel->sock);
        channel->sock = -1;
    }

    return 0;
}

void base_message_channel_start(void* target) {
    assert(target);
    struct base_message_channel* channel = (struct base_message_channel *) target;

    atomic_set(&channel->running, 1);
}

void base_message_channel_stop(void* target) {
    assert(target);
    struct base_message_channel* channel = (struct base_message_channel *) target;

    if(atomic_read(&channel->running)) {
        atomic_set(&channel->running, 0);
        task_unblock(channel->sock, FD_ALL);
        task_remove(channel->recv_task);
    }
}

int base_message_channel_register_callback(void* target, message_channel_callback* cb) {
    assert(target);
    assert(cb);
    struct base_message_channel* channel = (struct base_message_channel *) target;
    if(channel->callback.target) {
        return -1;
    }
    channel->callback = *cb;
    return 0;
}
int base_message_channel_unregister_callback(void* target, message_channel_callback* cb) {
    assert(target);
    assert(cb);
    struct base_message_channel* channel = (struct base_message_channel *) target;
    if(channel->callback.target == cb->target) {
        channel->callback.target = NULL;
        channel->callback.recv_message = NULL;
        return 0;
    }
    return -1;
}
int base_message_channel_get_callback_count(void* target) {
    assert(target);
    struct base_message_channel* channel = (struct base_message_channel *) target;
    return channel->callback.target == NULL ? 0 : 1;
}

