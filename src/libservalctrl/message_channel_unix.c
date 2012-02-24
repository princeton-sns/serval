/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <sys/un.h>
#include <assert.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <common/platform.h>
#include <common/atomic.h>
#include <common/debug.h>
#include <serval/ctrlmsg.h>
#include <libservalctrl/message_channel.h>
#include <libservalctrl/task.h>
#include "message_channel_internal.h"
#include "message_channel_base.h"

static void message_channel_unix_finalize(message_channel_t *channel)
{
    message_channel_base_t *base = (message_channel_base_t *)channel;

    message_channel_base_finalize(channel);

    if (strcmp(base->local.un.sun_path, SERVAL_CLIENT_CTRL_PATH) == 0) {
        unlink(SERVAL_CLIENT_CTRL_PATH);
    }
}

struct message_channel_ops unix_ops = {
    .initialize = message_channel_base_initialize,
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
    .recv = message_channel_internal_recv,
};

message_channel_base_t *message_channel_unix_create(channel_key_t *key)
{
    return message_channel_base_create(key, &unix_ops);
}
