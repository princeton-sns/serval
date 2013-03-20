
/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- 
 *
 * Netlink-based backend for message channels.
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
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <common/platform.h>
#include <common/atomic.h>
#include <common/debug.h>
#include <serval/ctrlmsg.h>
#include <libservalctrl/message_channel.h>
#include "message_channel_internal.h"
#include "message_channel_base.h"

/*
 * Mutability:
 * once created, the channel attributes are immutable
 *
 * Concurrency:
 * in general, there should only be a single
 * read task/thread and potentially multiple
 * send tasks/threads.
 *
 * Note that child processes should not inherit
 * message channels since the pid is the parent
 */

typedef struct message_channel_netlink {
    struct message_channel_base base;
    int reliable;
    atomic_t seq_num;
    atomic_t ack_num;		/* used for reliability and response signaling */
    atomic_t skip_num;
    uint64_t ack_buffer;	/* not sure if this bitmap is enough */
    uint64_t skip_buffer;
} message_channel_netlink_t;

static inline void skip_seq_num(message_channel_netlink_t *mcn, uint32_t seq_num)
{
    uint32_t skip, diff;

    skip = atomic_read(&mcn->skip_num);
    
    if (skip == 0) {
        skip = seq_num - 1;
        atomic_set(&mcn->skip_num, skip);
    }
    
    diff = seq_num - skip - 1;
    mcn->skip_buffer |= 1 << diff;
}

static inline int is_acked(message_channel_netlink_t *mcn,
                           unsigned int seq_num)
{
    /* atomic check for seq num */
    if (atomic_read(&mcn->ack_num) >= seq_num)
        return 1;

    return 0;
}

#if 0
static void recv_ack(message_channel_netlink_t *mcn,
                     unsigned int seq_num)
{
    unsigned int ack_num = atomic_read(&mcn->ack_num);
    int should_notify = 0;

    LOG_DBG("Received ACK %u ack_num=%u\n", seq_num, ack_num);

check_ack_num:
    if (ack_num == seq_num - 1) {
        int inc = 1;

        /* no one else will try to ack the given seq_num */
        should_notify = 1;
        
        /*the uncommon case where bad seq num's are skipped */
        if (atomic_read(&mcn->skip_num)) {
            uint64_t sbuff;
            uint32_t sdiff;

            sbuff = mcn->skip_buffer;
            sdiff = atomic_read(&mcn->skip_num) - ack_num;

            if (sdiff > 0) {
                sbuff <<= sdiff - 1;
            } else {
                //TODO - error!
            }

            while (mcn->ack_buffer & 0x1 || sbuff & 0x1) {
                inc += 1;
                mcn->ack_buffer >>= 1;
                sbuff >>= 1;
            }

            if (sbuff == 0) {
                atomic_set(&mcn->skip_num, 0);
            }

            atomic_add_return(inc, &mcn->ack_num);
        } else if (mcn->ack_buffer) {
            while (mcn->ack_buffer & 0x1) {
                inc += 1;
                mcn->ack_buffer >>= 1;
            }

            atomic_add_return(inc, &mcn->ack_num);
        }

        atomic_inc_return(&mcn->ack_num);

    } else {
        uint32_t diff;

        /* check if the skip is the next "ack" */
        if (atomic_read(&mcn->skip_num)) {
            uint32_t sdiff;

            sdiff = atomic_read(&mcn->skip_num) - ack_num;

            /* should be no need to "ack" more than the next bit as
             * future acks, if any, will catch the remaining skip bits
             */
            if (sdiff == 0) {
                if (mcn->skip_buffer & 0x1) {
                    should_notify = 1;
                    atomic_inc_return(&mcn->ack_num);
                    ack_num++;

                    mcn->skip_buffer &= ~0x1;
                    if (mcn->skip_buffer == 0) {
                        atomic_set(&mcn->skip_num, 0);
                    }

                    goto check_ack_num;
                }
            }
        }

        diff = seq_num - ack_num - 1;

        if (diff > sizeof(mcn->ack_buffer) * 8) {
            /* ack buffer exceeded! */
            LOG_ERR("Ack buffer exceeded: ack_num: %u seq_num: %u",
                    ack_num, seq_num);
            goto out;
        }

        diff = 1 << diff;

        mcn->ack_buffer |= diff;
    }

out:
}
#endif /* 0 */

static int netlink_send_internal(message_channel_netlink_t *mcn,
                                 struct iovec *iov, size_t veclen, 
                                 size_t datalen)
{
    int ret;
    uint32_t msgseq = ((struct nlmsghdr *) iov[0].iov_base)->nlmsg_seq;

    pthread_mutex_lock(&mcn->base.channel.lock);

    ret = message_channel_base_send_iov(&mcn->base.channel, 
                                        iov, veclen, datalen);

    if (mcn->reliable) {
        if (ret <= 0) {
            /* ensure that the messaging sequence is properly preserved */
            skip_seq_num(mcn, msgseq);
        } else {
            
            /*
              Not sure what the point of waiting for an ACK here is
              since we are not doing timeouts and retransmissions?
              Waiting for an ACK basically allows us to tell the app
              that the kernel received the message, but what about
              failures? We can decide that there was a failure after
              some arbitrary timeout, but, in that case, the app must
              anyhow handle that by itself, so why not let the app
              deal with reliability altogether?
            
            while (!is_acked(mcn, msgseq)) { LOG_DBG("Waiting for
            ACK\n"); sleep(1);
                //task_cond_wait(&mcn->cond, &mcn->base.lock);
            }
            */
        }
    }
    pthread_mutex_unlock(&mcn->base.channel.lock);

    return ret;
}

static int netlink_send_iov(message_channel_t *channel, 
                            struct iovec *iov,
                            size_t veclen, size_t datalen)
{
    message_channel_netlink_t *mcn = (message_channel_netlink_t *)channel;
    struct iovec *vec;
    struct nlmsghdr nh;
    int ret;

    assert(channel);

    if (!iov)
        return -1;

    if (datalen == 0 || veclen == 0)
        return 0;

    /* LOG_DBG("Sending NETLINK %zu byte message to the local stack\n", 
            datalen);
    */
    vec = (struct iovec *) malloc((veclen + 1) * sizeof(*vec));
    
    if (!vec)
        return -1;

    memset(&nh, 0, sizeof(nh));
    memcpy(vec + 1, iov, veclen * sizeof(*vec));
    vec[0].iov_base = &nh;
    vec[0].iov_len = sizeof(nh);
    
    nh.nlmsg_type = NLMSG_MIN_TYPE;
    nh.nlmsg_flags = NLM_F_REQUEST;
    nh.nlmsg_pid = mcn->base.peer.nl.nl_pid;
    nh.nlmsg_seq = atomic_inc_return(&mcn->seq_num);
    nh.nlmsg_len = NLMSG_LENGTH(datalen);

    /* Request an ack from kernel by setting NLM_F_ACK. */
    if (mcn->reliable) {
        nh.nlmsg_flags |= NLM_F_ACK;
    }
    ret = netlink_send_internal(mcn, vec, veclen + 1, datalen);

    free(vec);

    return ret;
}

static int netlink_send(message_channel_t *channel, void *message,
                        size_t datalen)
{
    message_channel_netlink_t *mcn = (message_channel_netlink_t *)channel;
    struct nlmsghdr nh;
    struct iovec iov[2] = { { &nh, sizeof(nh) },
                            { message, datalen } };

    assert(channel);

    /* LOG_DBG("Sending NETLINK %zu byte message to the local stack\n", datalen); */

    memset(&nh, 0, sizeof(nh));
    nh.nlmsg_type = NLMSG_MIN_TYPE;
    nh.nlmsg_flags = NLM_F_REQUEST;
    nh.nlmsg_pid = mcn->base.peer.nl.nl_pid;
    nh.nlmsg_seq = atomic_inc_return(&mcn->seq_num);
    nh.nlmsg_len = NLMSG_LENGTH(datalen);

    /* Request an ack from kernel by setting NLM_F_ACK. */
    if (mcn->reliable) {
        nh.nlmsg_flags |= NLM_F_ACK;
    }

    return netlink_send_internal(mcn, iov, 2, datalen);
}

static ssize_t netlink_recv(message_channel_t *channel, struct message **msg)
{
    message_channel_netlink_t *mcnl = (message_channel_netlink_t *)channel;
    struct nlmsghdr *nlm;
    unsigned int num_msgs = 0;
    long bytes_left;
    message_t *m;
    ssize_t ret;

    m = message_alloc(NULL, RECV_BUFFER_SIZE);
    
    if (!m)
        return -1;

    
    ret = recvfrom(mcnl->base.sock, m->data,
                   m->length, 0,
                   &m->from.sa, &m->from_len);

    bytes_left = ret;

    /* Channel already locked by receiver task */
     /*LOG_DBG("Received NETLINK %zu byte message from the local stack\n",
       datalen);*/

    ret = -1;

    for (nlm = (struct nlmsghdr *)m->data;
         NLMSG_OK(nlm, bytes_left);
         nlm = NLMSG_NEXT(nlm, bytes_left)) {
        struct nlmsgerr *nlmerr = NULL;

        num_msgs++;
        
        /* check for ack'ing */

        /* sanity check */
        /*
        if (nlm->nlmsg_pid != mcn->base.local.nl.nl_pid) {
            LOG_ERR("NL message received for wrong PID: %d != %d\n",
                    nlm->nlmsg_pid, mcn->base.peer.nl.nl_pid);
            continue;
        }
        */

        switch (nlm->nlmsg_type) {
        case NLMSG_NOOP:
            LOG_DBG("NLMSG NOOP\n");
            break;
        case NLMSG_ERROR:
            LOG_DBG("NLMSG ERROR\n");
            nlmerr = (struct nlmsgerr *) NLMSG_DATA(nlm);
            if (nlmerr->error == 0) {
                /*
                if (mcn->reliable)
                    recv_ack(mcn, nlm->nlmsg_seq);
                */
            } else {
                LOG_DBG("NLMSG_ERROR, error=%d type=%d\n",
                        nlmerr->error, nlmerr->msg.nlmsg_type);
            }
            break;
        case NLMSG_DONE:
            break;
        case NLMSG_SERVAL:
            /* Strip off netlink headers */
            memmove(m->data, NLMSG_DATA(nlm), bytes_left - NLMSG_LENGTH(0));
            m->length = bytes_left - NLMSG_LENGTH(0);
            ret = bytes_left - NLMSG_LENGTH(0);
            break;
        default:
            LOG_DBG("Unknown netlink message\n");
            break;
        }
    }

    if (ret <= 0)
        message_put(m);
    else {
        *msg = m;
    }

    return ret;
}

message_channel_ops_t netlink_ops = {
    .initialize = message_channel_base_initialize,
    .start = message_channel_base_start,
    .stop = message_channel_base_stop,
    .finalize = message_channel_base_finalize,
    .hold = message_channel_internal_hold,
    .put = message_channel_internal_put,
    .hashfn = message_channel_internal_hashfn,
    .equalfn = message_channel_base_equalfn,
    .fillkey = message_channel_base_fillkey,
    .get_local = message_channel_base_get_local,
    .set_peer = message_channel_base_set_peer,
    .get_peer = message_channel_base_get_peer,
    .register_callback = message_channel_internal_register_callback,
    .unregister_callback = message_channel_internal_unregister_callback,
    .get_callback_count = message_channel_internal_get_callback_count,
    .send = netlink_send,
    .send_iov = netlink_send_iov,
    .recv = netlink_recv,
    .recv_callback = message_channel_internal_recv_callback,
    .task = message_channel_base_task,
};

message_channel_t *message_channel_netlink_create(channel_key_t *key)
{
    return message_channel_base_create(key, 
                                       sizeof(message_channel_netlink_t),
                                       &netlink_ops);
}
