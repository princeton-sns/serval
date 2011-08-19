/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
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

#include <serval/platform.h>
#include <serval/atomic.h>
#include "debug.h"
#include "service_util.h"
#include "task.h"
#include "message_channel_base.h"

int base_message_channel_initialize(message_channel * channel)
{
    assert(channel);
    if (!is_created(channel->channel.state)) {
	return -1;
    }
    struct sv_message_channel_base *base =
	(struct sv_message_channel_base *) channel;
    base->buffer = (char *) malloc(base->buffer_len);
    bzero(base->buffer, base->buffer_len);
    channel->channel.state = COMP_INITIALIZED;
    return 0;
}

int base_message_channel_finalize(message_channel * channel)
{
    assert(channel);
    struct sv_message_channel_base *base =
	(struct sv_message_channel_base *) channel;

    if (atomic_read(&base->running)) {
	base_message_channel_stop(channel);
    }

    if (base->buffer) {
	free(base->buffer);
	base->buffer = NULL;
    }

    if (base->sock > 0) {
	close(base->sock);
	base->sock = -1;
    }

    channel->channel.state = COMP_CREATED;
    return 0;
}

void base_message_channel_start(message_channel * channel)
{
    assert(channel);
    struct sv_message_channel_base *base =
	(struct sv_message_channel_base *) channel;

    atomic_set(&base->running, 1);
    channel->channel.state = COMP_STARTED;
}

void base_message_channel_stop(message_channel * channel)
{
    assert(channel);
    if (!is_started(channel->channel.state)) {
	return;
    }
    struct sv_message_channel_base *base =
	(struct sv_message_channel_base *) channel;

    if (atomic_read(&base->running)) {
	atomic_set(&base->running, 0);
	task_unblock(base->sock, FD_ALL);
	task_remove(base->recv_task);
    }
}

int base_message_channel_register_callback(message_channel * channel,
					   message_channel_callback * cb)
{
    assert(channel);
    assert(cb);
    struct sv_message_channel_base *base =
	(struct sv_message_channel_base *) channel;
    if (base->callback.target) {
	return -1;
    }
    base->callback = *cb;
    return 0;
}

int base_message_channel_unregister_callback(message_channel * channel,
					     message_channel_callback * cb)
{
    assert(channel);
    assert(cb);
    struct sv_message_channel_base *base =
	(struct sv_message_channel_base *) channel;
    if (base->callback.target == cb->target) {
	base->callback.target = NULL;
	base->callback.recv_message = NULL;
	return 0;
    }
    return -1;
}

int base_message_channel_get_callback_count(message_channel * channel)
{
    assert(channel);
    struct sv_message_channel_base *base =
	(struct sv_message_channel_base *) channel;
    return base->callback.target == NULL ? 0 : 1;
}
