/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- 
 *
 * UNIX domain socket backend for message channels.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 *          David Shue <dshue@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#include <assert.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <common/platform.h>
#include <common/atomic.h>
#include <common/debug.h>
#include <serval/ctrlmsg.h>
#include <libservalctrl/message_channel.h>
#include "message_channel_internal.h"
#include "message_channel_base.h"

static void message_channel_unix_finalize(message_channel_t *channel)
{
    message_channel_base_t *base = (message_channel_base_t *)channel;
    message_channel_base_finalize(channel);
    unlink(base->local.un.sun_path);
}

static int message_channel_unix_initialize(message_channel_t *channel)
{
    struct ctrlmsg cm;
    message_channel_base_t *base = (message_channel_base_t *)channel;
    ssize_t ret;

    message_channel_base_initialize(channel);

    /* Send a dummy message to make the stack aware of this channel
       client */
    memset(&cm, 0, sizeof(cm));
    cm.type = CTRLMSG_TYPE_DUMMY;
    cm.len = sizeof(cm);

    ret = sendto(base->sock, &cm, cm.len, 0, 
                 &base->peer.sa, base->peer_len);
    
    if (ret == -1) {
        LOG_ERR("%s could not send hello message on channel: %s\n",
                channel->name, strerror(errno));
    }

    return ret >= 0 ? 0 : ret;
}

struct message_channel_ops unix_ops = {
    .initialize = message_channel_unix_initialize,
    .start = message_channel_base_start,
    .stop = message_channel_base_stop,
    .finalize = message_channel_unix_finalize,
    .hashfn = message_channel_internal_hashfn,
    .equalfn = message_channel_base_equalfn,
    .fillkey = message_channel_base_fillkey,
    .hold = message_channel_internal_hold,
    .put = message_channel_internal_put,
    .get_local = message_channel_base_get_local,
    .set_peer = message_channel_base_set_peer,
    .get_peer = message_channel_base_get_peer,
    .register_callback = message_channel_internal_register_callback,
    .unregister_callback = message_channel_internal_unregister_callback,
    .get_callback_count = message_channel_internal_get_callback_count,
    .send = message_channel_base_send,
    .send_iov = message_channel_base_send_iov,
    .recv = message_channel_base_recv,
    .recv_callback = message_channel_internal_recv_callback,
    .task = message_channel_base_task,
};

message_channel_t *message_channel_unix_create(channel_key_t *key)
{
    return message_channel_base_create(key, sizeof(message_channel_base_t),
                                       &unix_ops);
}
