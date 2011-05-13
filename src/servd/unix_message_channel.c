/*
 * unix_message_channel.c
 *
 *  Created on: Feb 15, 2011
 *      Author: daveds
 */
#include <sys/un.h>
#include <libstack/ctrlmsg.h>
#include <sys/un.h>
#include <serval/platform.h>
#include <serval/atomic.h>
#include <assert.h>
#include <string.h>
#include "debug.h"
#include <sys/socket.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "service_util.h"
#include "task.h"
#include "message_channel.h"
#include "message_channel_base.h"
#define UNIX_BUFFER_SIZE 2048

/* note that the unix message channel only supports point-to-point communication
 * and does not support receiving packets from multiple peers.
 */

struct sv_unix_message_channel {
    struct base_message_channel base;
    atomic_t running;
    //char local_path[104];
    //char remote_path[104];
    struct sockaddr_un local;
    struct sockaddr_un peer;

};

static int unix_initialize(void* channel);
static void unix_start(void* channel);
static int unix_finalize(void* channel);
static const struct sockaddr* unix_get_local_address(void* target, int* len);
static void unix_set_peer_address(void* target, struct sockaddr* addr, size_t len);
static const struct sockaddr* unix_get_peer_address(void* target, int* len);
static int unix_send(void* channel, void *message, size_t datalen);
static int
unix_send_iov(void* channel, struct iovec* iov, size_t veclen, size_t datalen);

static int unix_recv(void* channel, const void *message, size_t datalen);
static void unix_recv_task(void* channel);

static struct sv_message_channel_interface unix_mc_interface = {
        .initialize = unix_initialize,
        .start = unix_start,
        .stop = base_message_channel_stop,
        .finalize = unix_finalize,
        .get_local_address = unix_get_local_address,
        .set_peer_address = unix_set_peer_address,
        .get_peer_address = unix_get_peer_address,
        .register_callback = base_message_channel_register_callback,
        .unregister_callback = base_message_channel_unregister_callback,
        .get_callback_count = base_message_channel_get_callback_count,
        .send_message = unix_send,
        .send_message_iov = unix_send_iov,
        .recv_message = unix_recv };

void create_unix_message_channel(const char* lpath, const char* rpath, int buffer_len,
        message_channel_callback* callback, message_channel* channel) {

    struct sv_unix_message_channel* uchannel = (struct sv_unix_message_channel *) malloc(
            sizeof(struct sv_unix_message_channel));

    if(uchannel == NULL) {
        LOG_ERR("Could not allocate memory for unix message channel");
        return;
    }

    bzero(uchannel, sizeof(*uchannel));

    if(buffer_len > 0) {
        uchannel->base.buffer_len = buffer_len;
    } else {
        uchannel->base.buffer_len = UNIX_BUFFER_SIZE;
    }

    uchannel->peer.sun_family = AF_UNIX;
    uchannel->local.sun_family = AF_UNIX;

    strcpy(uchannel->local.sun_path, lpath);
    strcpy(uchannel->peer.sun_path, rpath);

    uchannel->base.callback = *callback;

    channel->target = uchannel;
    channel->interface = &unix_mc_interface;
}

static void unix_set_peer_address(void* target, struct sockaddr* addr, size_t len) {
    assert(target);
    /* TODO threading issues? */
    if(addr == NULL || len != sizeof(struct sockaddr_un)) {
        return;
    }

    struct sv_unix_message_channel* uchannel = (struct sv_unix_message_channel*) target;

    /* family is set - only change the remote socket address */
    struct sockaddr_un* saddr = (struct sockaddr_un*) addr;

    /* sanity check the length? */
    //strcpy(uchannel->remote_path, saddr->sun_path);
    // only applicable on BSD uchannel->peer.sun_len = saddr->sun_len;
    strcpy(uchannel->peer.sun_path, saddr->sun_path);

}

static const struct sockaddr* unix_get_peer_address(void* target, int* len) {
    assert(target);

    struct sv_unix_message_channel* uchannel = (struct sv_unix_message_channel*) target;
    *len = sizeof(struct sockaddr_un);

    return (struct sockaddr*) &uchannel->peer;
}

static const struct sockaddr* unix_get_local_address(void* target, int* len) {
    assert(target);
    struct sv_unix_message_channel* uchannel = (struct sv_unix_message_channel*) target;
    *len = sizeof(struct sockaddr_un);

    return (struct sockaddr*) &uchannel->local;
}

static int unix_initialize(void* channel) {
    assert(channel);

    struct sv_unix_message_channel* uchannel = (struct sv_unix_message_channel*) channel;
    base_message_channel_initialize(uchannel);

    int ret = 0;

    LOG_DBG("initializing SERVAL unix control\n");

    /* set the sockaddr_un sun_len? TODO */

    uchannel->base.sock = socket(AF_UNIX, SOCK_DGRAM, 0);

    if(uchannel->base.sock == -1) {
        LOG_ERR("Serval unix socket failure: %s\n", strerror(errno));
        goto error_sock;
    }

    ret = bind(uchannel->base.sock, (struct sockaddr *) &uchannel->local, sizeof(uchannel->local));

    if(ret == -1) {
        LOG_ERR("bind failed: %s\n", strerror(errno));
        goto error_bind;
    }

    /* the default is async/non-block?*/
    ret = make_async(uchannel->base.sock);

    if(ret == -1) {
        LOG_ERR("make_async failed: %s\n", strerror(errno));
        goto error_bind;
    }

    /* Now set the address to point to the stack */
//    struct sockaddr_un testaddr;
//    bzero(&testaddr, sizeof(struct sockaddr_un));
//    strcpy(testaddr.sun_path, uchannel->remote_path);

    /*
     Use the connect call to see if there is a control
     socket available. This means the userlevel Serval
     daemon is running. Since we are not a STREAM socket
     the connection will fail, but that is our cue that
     Serval is running.

     Could this be accomplished by a sendto?
     */
    ret = connect(uchannel->base.sock, (struct sockaddr *) &uchannel->peer, sizeof(uchannel->peer));

    if(ret == -1) {
        if(errno == ENOENT) {
            /* This probably means we are not running the
             * user space version of the Serval stack,
             * therefore unregister this handler and exit
             * without error. */LOG_DBG("Serval unix control not supported, disabling\n");
            goto error_connect;
        } else if(errno == ECONNREFUSED) {
            /* Success, daemon is running */LOG_DBG("Serval unix connection refused\n");
            ret = 0;
        } else {
            LOG_ERR("Serval unix connect error: %s\n", strerror(errno));
            goto error_connect;
        }
    }

    return ret;
    //out: return ret;
    //exception handling
    //clean up the path
    error_connect: error_bind: unix_finalize(uchannel);
    error_sock: return ret;
}

static void unix_start(void* channel) {
    assert(channel);

    struct sv_unix_message_channel* uchannel = (struct sv_unix_message_channel*) channel;
    base_message_channel_start(uchannel);

    uchannel->base.recv_task = task_add(uchannel, unix_recv_task);
}

static int unix_finalize(void* channel) {
    assert(channel);

    struct sv_unix_message_channel* uchannel = (struct sv_unix_message_channel*) channel;
    base_message_channel_finalize(uchannel);
    unlink(uchannel->local.sun_path);

    return 0;
}

static int unix_send(void* channel, void *message, size_t datalen) {
    assert(channel);
    if(message == NULL) {
        return EINVAL;
    }
    if(datalen == 0) {
        return 0;
    }

    LOG_DBG("Sending UNIX %i byte message to the local stack\n", datalen);

    struct sv_unix_message_channel* uchannel = (struct sv_unix_message_channel*) channel;

    int ret = -1;
    int retries = 0;

    while(atomic_read(&uchannel->base.running) && ret < 0 && retries <= MAX_MESSAGE_RETRIES) {

        ret = sendto(uchannel->base.sock, message, datalen, 0, (struct sockaddr*) &uchannel->peer,
                sizeof(uchannel->peer));

        if(ret == -1) {
            if(errno == EWOULDBLOCK || errno == EAGAIN) {
                task_block(uchannel->base.sock, FD_WRITE);
                continue;
            } else {
                LOG_DBG("recvmsg error: %s\n", strerror(errno));
                return ret;
            }
        }
    }

    return ret;
}

static int unix_send_iov(void* channel, struct iovec* iov, size_t veclen, size_t datalen) {
    assert(channel);
    if(iov == NULL) {
        return EINVAL;
    }
    if(veclen == 0 || datalen == 0) {
        return 0;
    }

    LOG_DBG("Sending UNIX %i byte message to the local stack\n", datalen);

    struct sv_unix_message_channel* uchannel = (struct sv_unix_message_channel*) channel;
    struct msghdr mh = { &uchannel->peer, sizeof(uchannel->peer), iov, veclen, NULL, 0, 0 };
    //return ;
    int ret = -1;

    int retries = 0;

    while(atomic_read(&uchannel->base.running) && ret < 0 && retries <= MAX_MESSAGE_RETRIES) {
        ret = sendmsg(uchannel->base.sock, &mh, 0);

        if(ret == -1) {
            if(errno == EWOULDBLOCK || errno == EAGAIN) {
                task_block(uchannel->base.sock, FD_WRITE);
                continue;
            } else {
                LOG_DBG("recvmsg error: %s\n", strerror(errno));
                return ret;
            }
        }
    }

    return ret;
}

static int unix_recv(void* channel, const void *message, size_t datalen) {
    assert(channel);

    struct sv_unix_message_channel* uchannel = (struct sv_unix_message_channel*) channel;

    uchannel->base.callback.recv_message(uchannel->base.callback.target, message, datalen);
    return 0;
}

/* single threaded receive! */
static void unix_recv_task(void* channel) {
    assert(channel);

    struct sv_unix_message_channel* uchannel = (struct sv_unix_message_channel*) channel;

    socklen_t addr_len = 0;
    int ret = 1;

    //bzero(uchannel->base.buffer, uchannel->base.buffer_len);

    //perpetual read loop
    while(atomic_read(&uchannel->base.running) && ret) {
        //TODO - could have a race condition here with FINI
        //MSG_DONTWAIT
        ret = recvfrom(uchannel->base.sock, uchannel->base.buffer, uchannel->base.buffer_len, 0,
                (struct sockaddr *) &uchannel->peer, &addr_len);

        if(ret == -1) {
            if(errno == EWOULDBLOCK || errno == EAGAIN) {
                task_block(uchannel->base.sock, FD_READ);
                continue;
            }

            LOG_DBG("SERVAL unix recvmsg error: %s\n", strerror(errno));
            goto error;
        }

        //TODO - what if ret is 0?
        /* note that if the message is to be cached, it must be copied */
        unix_recv(channel, uchannel->base.buffer, ret);
    }

    error: atomic_set(&uchannel->running, 0);

    return;
}

