/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * unix_message_channel.c
 *
 *  Created on: Feb 15, 2011
 *      Author: daveds
 */
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

#if 0
static int message_channel_unix_initialize(message_channel_t *channel)
{
    message_channel_base_t *base = (message_channel_base_t *)channel;
    int ret;

    assert(channel);

    base->sock_type = SOCK_DGRAM;

    ret = message_channel_base_initialize(channel);

    if (ret)
        return ret;

    /*
      Use the connect call to see if there is a control
      socket available. This means the userlevel Serval
      daemon is running. Since we are not a STREAM socket
      the connection will fail, but that is our cue that
      Serval is running.

      Could this be accomplished by a sendto?
    */
    ret = connect(base->sock, (struct sockaddr *) &base->peer,
                  sizeof(base->peer));

    if (ret == -1) {
        if (errno == ENOENT) {
            /* This probably means we are not running the
             * user space version of the Serval stack,
             * therefore unregister this handler and exit
             * without error. */
            LOG_DBG("Serval unix control not supported, disabling\n");
            goto error_connect;
        } else if (errno == ECONNREFUSED) {
            /* Success, daemon is running */
            LOG_DBG("Serval unix connection refused\n");
            ret = 0;
        } else {
            LOG_ERR("Serval unix connect error: %s\n", strerror(errno));
            goto error_connect;
        }
    }

    return ret;
error_connect: 
    channel->ops->finalize(channel);
    return ret;
}
#endif /* DISABLED */

struct message_channel_ops unix_ops = {
    .initialize = message_channel_base_initialize,
    .start = message_channel_base_start,
    .stop = message_channel_base_stop,
    .finalize = message_channel_base_finalize,
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
