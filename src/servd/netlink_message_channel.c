/*
 * service_path.c
 *
 *  Created on: Feb 14, 2011
 *      Author: daveds
 */

#include <assert.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include "libstack/ctrlmsg.h"
#include "serval/platform.h"
#include "serval/atomic.h"
#include "debug.h"
#include "service_util.h"
#include "task.h"
#include "message_channel.h"
#include "message_channel_base.h"

#define NETLINK_BUFFER_SIZE 2048

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

struct sv_netlink_message_channel {
    struct base_message_channel base;
    int protocol;
    int pid;
    atomic_t seq_num;
    struct sockaddr_nl peer;

    int reliable;
    atomic_t ack_num; /* used for reliability and response signaling */
    atomic_t skip_num;
    uint64_t ack_buffer; /* not sure if this bitmap is enough */
    uint64_t skip_buffer;
    task_cond cond;
    task_mutex mutex;
};

static int netlink_initialize(void* channel);
static void netlink_start(void* channel);
static int netlink_finalize(void* channel);
static const struct sockaddr* netlink_get_local_address(void* target, int* len);
static void netlink_set_peer_address(void* target, struct sockaddr* addr, size_t len);
static const struct sockaddr* netlink_get_peer_address(void* target, int* len);
static int netlink_send(void* channel, void *message, size_t datalen);
static int
netlink_send_iov(void* channel, struct iovec* iov, size_t veclen, size_t datalen);

static int netlink_recv(void* channel, const void *message, size_t datalen);
static void netlink_recv_task(void* channel);

static struct sv_message_channel_interface netlink_mc_interface = {
        .initialize = netlink_initialize,
        .start = netlink_start,
        .stop = base_message_channel_stop,
        .finalize = netlink_finalize,
        .get_local_address = netlink_get_local_address,
        .set_peer_address = netlink_set_peer_address,
        .get_peer_address = netlink_get_peer_address,
        .register_callback = base_message_channel_register_callback,
        .unregister_callback = base_message_channel_unregister_callback,
        .get_callback_count = base_message_channel_get_callback_count,
        .send_message = netlink_send,
        .send_message_iov = netlink_send_iov,
        .recv_message = netlink_recv };

static int _netlink_send(void* channel, struct iovec* iov, size_t veclen);

static inline void skip_seq_num(struct sv_netlink_message_channel* nchannel, uint32_t seq_num) {
    task_mutex_lock(&nchannel->mutex);

    uint32_t skip = atomic_read(&nchannel->skip_num);

    if(skip == 0) {
        skip = seq_num - 1;
        atomic_set(&nchannel->skip_num, skip);
    }
    uint32_t diff = seq_num - skip - 1;
    nchannel->skip_buffer |= 1 << diff;

    task_mutex_unlock(&nchannel->mutex);
}

static inline int is_acked(struct sv_netlink_message_channel* nchannel, uint32_t seq_num) {
    /* atomic check for seq num */
    if(atomic_read(&nchannel->ack_num) >= seq_num) {
        return TRUE;
    }

    return FALSE;
}

/* only called by read - single thread/task */
static void ack_seq_num(struct sv_netlink_message_channel* nchannel, uint32_t seq_num) {
    uint32_t ack_num = atomic_read(&nchannel->ack_num);

    int should_notify = 0;
    check_ack_num: if(ack_num == seq_num - 1) {
        /* no one else will try to ack the given seq_num */
        should_notify = 1;
        int inc = 1;
        /*the uncommon case where bad seq num's are skipped */
        if(atomic_read(&nchannel->skip_num)) {
            task_mutex_lock(&nchannel->mutex);

            uint64_t sbuff = nchannel->skip_buffer;
            uint32_t sdiff = atomic_read(&nchannel->skip_num) - ack_num;
            if(sdiff > 0) {
                sbuff <<= sdiff - 1;
            } else {
                //TODO - error!
            }

            while (nchannel->ack_buffer & 0x1 || sbuff & 0x1) {
                inc += 1;
                nchannel->ack_buffer >>= 1;
                sbuff >>= 1;
            }

            if(sbuff == 0) {
                atomic_set(&nchannel->skip_num, 0);
            }

            atomic_add_return(inc, &nchannel->ack_num);
            task_mutex_unlock(&nchannel->mutex);
        } else if(nchannel->ack_buffer) {
            while (nchannel->ack_buffer & 0x1) {
                inc += 1;
                nchannel->ack_buffer >>= 1;
            }

            atomic_add_return(inc, &nchannel->ack_num);
        }

        atomic_inc_return(&nchannel->ack_num);

    } else {

        /* check if the skip is the next "ack" */
        if(atomic_read(&nchannel->skip_num)) {
            task_mutex_lock(&nchannel->mutex);
            uint32_t sdiff = atomic_read(&nchannel->skip_num) - ack_num;

            /* should be no need to "ack" more than the next bit as future
             * acks, if any, will catch the remaining skip bits
             */
            if(sdiff == 0) {
                if(nchannel->skip_buffer & 0x1) {
                    should_notify = 1;
                    atomic_inc_return(&nchannel->ack_num);
                    ack_num++;

                    nchannel->skip_buffer &= ~0x1;
                    if(nchannel->skip_buffer == 0) {
                        atomic_set(&nchannel->skip_num, 0);
                    }

                    task_mutex_unlock(&nchannel->mutex);
                    goto check_ack_num;
                }
            }

            task_mutex_unlock(&nchannel->mutex);
        }

        uint32_t diff = seq_num - ack_num - 1;

        if(diff > sizeof(nchannel->ack_buffer) * 8) {
            /* ack buffer exceeded! */LOG_ERR("Ack buffer exceeded: ack_num: %u seq_num: %u", ack_num, seq_num);
            goto out;
        }

        diff = 1 << diff;

        nchannel->ack_buffer |= diff;
    }

    out: if(should_notify) {
        task_cond_notify(&nchannel->cond);
    }
    return;

    /*errors?*/
}

void create_netlink_message_channel(int protocol, int buffer_len, int reliable,
        message_channel_callback* callback, message_channel* channel) {
    struct sv_netlink_message_channel* nchannel = (struct sv_netlink_message_channel *) malloc(
            sizeof(struct sv_netlink_message_channel));

    if(nchannel == NULL) {
        LOG_ERR("Could not allocate netlink message channel memory");
        return;
    }

    bzero(nchannel, sizeof(*nchannel));
    nchannel->protocol = protocol;
    nchannel->pid = getpid();

    if(buffer_len > 0) {
        nchannel->base.buffer_len = buffer_len;
    } else {
        nchannel->base.buffer_len = NETLINK_BUFFER_SIZE;
    }

    if(reliable) {
        nchannel->reliable = reliable;
    }

    nchannel->base.callback = *callback;

    channel->target = nchannel;
    channel->interface = &netlink_mc_interface;
}

static const struct sockaddr* netlink_get_local_address(void* target, int* len) {
    return NULL;
}

static void netlink_set_peer_address(void* target, struct sockaddr* addr, size_t len) {
    assert(target);

    struct sv_netlink_message_channel* nchannel = (struct sv_netlink_message_channel *) target;

    if(addr == NULL || len != sizeof(struct sockaddr_nl)) {
        return;
    }

    struct sockaddr_nl* naddr = (struct sockaddr_nl*) addr;
    nchannel->peer.nl_groups = naddr->nl_groups;
    nchannel->peer.nl_pid = naddr->nl_pid;
}

const struct sockaddr* netlink_get_peer_address(void* channel, int* len) {
    assert(channel);

    struct sv_netlink_message_channel* nchannel = (struct sv_netlink_message_channel *) channel;
    *len = sizeof(struct sockaddr_nl);
    return (struct sockaddr*) &nchannel->peer;
}

static int netlink_initialize(void* channel) {
    assert(channel);

    struct sv_netlink_message_channel* nchannel = (struct sv_netlink_message_channel *) channel;
    LOG_DBG("initializing SERVAL netlink control\n");

    int ret;

    base_message_channel_initialize(&nchannel->base);
    atomic_set(&nchannel->seq_num, 0);

    if(nchannel->reliable) {
        nchannel->ack_buffer = 0;
        atomic_set(&nchannel->ack_num, 0);
        //ATOMIC_INIT(&nchannel->ack_num);
    }

    nchannel->base.sock = socket(PF_NETLINK, SOCK_RAW, nchannel->protocol);

    if(nchannel->base.sock == -1) {
        if(errno == EPROTONOSUPPORT) {
            /* This probably means we are not running the
             * kernel space version of the Serval stack,
             * therefore unregister this handler and exit
             * without error. */LOG_DBG("netlink not supported, disabling\n");
            ret = -1;
            goto error;
        }

        LOG_ERR("netlink control failure: %s\n",
                strerror(errno));
        ret = -1;
        goto error;
    }
    nchannel->peer.nl_family = AF_NETLINK;
    nchannel->peer.nl_pid = nchannel->pid;
    /* the multicast group */
    nchannel->peer.nl_groups = 1;

    ret = bind(nchannel->base.sock, (struct sockaddr*) &nchannel->peer, sizeof(nchannel->peer));

    if(ret == -1) {
        LOG_ERR("Could not bind netlink control socket\n");
        goto error;
    }

    ret = make_async(nchannel->base.sock);

    if(ret == -1) {
        LOG_ERR("make_async failed: %s\n", strerror(errno));
        goto error;
    }

    /* Set peer address to indicate kernel as target */
    nchannel->peer.nl_pid = 0;
    nchannel->peer.nl_groups = 0;

    out: return ret;

    error: netlink_finalize(channel);
    goto out;
}

static void netlink_start(void* channel) {
    assert(channel);
    struct sv_netlink_message_channel* nchannel = (struct sv_netlink_message_channel *) channel;
    base_message_channel_start(&nchannel->base);
    nchannel->base.recv_task = task_add(nchannel, netlink_recv_task);
}

static int netlink_finalize(void* channel) {
    assert(channel);
    struct sv_netlink_message_channel* nchannel = (struct sv_netlink_message_channel *) channel;

    base_message_channel_finalize(&nchannel->base);
    return 0;
}

static int netlink_send_iov(void* channel, struct iovec* iov, size_t veclen, size_t datalen) {
    assert(channel);

    if(iov == NULL) {
        return EINVAL;
    }

    if(datalen == 0 || veclen == 0) {
        return 0;
    }
    struct sv_netlink_message_channel* nchannel = (struct sv_netlink_message_channel *) channel;

    LOG_DBG("Sending NETLINK %i byte message to the local stack\n", datalen);

    struct iovec* vec = (struct iovec*) malloc((veclen + 1) * sizeof(*vec));
    struct nlmsghdr nh;
    memcpy(vec + 1, iov, veclen * sizeof(*vec));
    vec[0].iov_base = (void*) &nh;
    vec[0].iov_len = sizeof(nh);

    bzero(&nh, sizeof(nh));

    /* netlink message to the kernel */
    int retval = 0;

    nh.nlmsg_pid = 0;
    nh.nlmsg_seq = atomic_inc_return(&nchannel->seq_num);
    nh.nlmsg_len = NLMSG_LENGTH(datalen);
    /* Request an ack from kernel by setting NLM_F_ACK. */
    if(nchannel->reliable) {
        nh.nlmsg_flags |= NLM_F_ACK;
    }

    retval = _netlink_send(channel, vec, veclen + 1);

    free(vec);
    return retval;
}

static int _netlink_send(void* channel, struct iovec* iov, size_t veclen) {

    struct sv_netlink_message_channel* nchannel = (struct sv_netlink_message_channel *) channel;
    struct msghdr mh = { &nchannel->peer, sizeof(nchannel->peer), iov, veclen, NULL, 0, 0 };

    /* datagram style sendmsg is thread-safe and should avoid message collision/mangling issues */
    int ret = -1;
    int retries = 0;

    uint32_t msgseq = ((struct nlmsghdr*) iov[0].iov_base)->nlmsg_seq;
    while (atomic_read(&nchannel->base.running) && ret < 0 && retries <= MAX_MESSAGE_RETRIES) {
        ret = sendmsg(nchannel->base.sock, &mh, 0);
        retries++;

        if(ret == -1) {
            if(errno == EAGAIN || errno == EWOULDBLOCK) {
                LOG_DBG("Netlink recv would block\n");
                task_block(nchannel->base.sock, FD_WRITE);
                continue;
            } else if(errno == ENOBUFS) {
                /* sleep for 100 ms until buffers free up? */
                task_sleep(100);
                continue;
            } else {
                if(nchannel->reliable) {
                    /* ensure that the messaging sequence is properly preserved */
                    skip_seq_num(nchannel, msgseq);
                }
                return ret;
            }
        }
    }

    //TODO check for 0?
    if(ret > 0 && nchannel->reliable) {
        while (!is_acked(nchannel, msgseq)) {
            task_cond_wait(&nchannel->cond, &nchannel->mutex);
        }
    }

    return ret;

}

static int netlink_send(void* channel, void *message, size_t datalen) {
    assert(channel);
    struct sv_netlink_message_channel* nchannel = (struct sv_netlink_message_channel *) channel;

    LOG_DBG("Sending NETLINK %i byte message to the local stack\n", datalen);

    struct nlmsghdr nh;
    struct iovec iov[2] = { { (void *) &nh, sizeof(nh) }, { (void *) message, datalen } };

    bzero(&nh, sizeof(nh));

    /* netlink message to the kernel */

    nh.nlmsg_pid = 0;
    nh.nlmsg_seq = atomic_inc_return(&nchannel->seq_num);
    nh.nlmsg_len = NLMSG_LENGTH(datalen);
    /* Request an ack from kernel by setting NLM_F_ACK. */
    if(nchannel->reliable) {
        nh.nlmsg_flags |= NLM_F_ACK;
    }

    return _netlink_send(channel, iov, 2);
}

static int netlink_recv(void* channel, const void *message, size_t datalen) {
    struct sv_netlink_message_channel* nchannel = (struct sv_netlink_message_channel *) channel;
    struct nlmsghdr* nlm;
    int num_msgs = 0;
    LOG_DBG("Received NETLINK %i byte message from the local stack\n", datalen);
    for (nlm = (struct nlmsghdr *) message; NLMSG_OK(nlm, (unsigned int) datalen); nlm
            = NLMSG_NEXT(nlm, datalen)) {
        struct nlmsgerr *nlmerr = NULL;
        num_msgs++;

        /* check for ack'ing */

        /* sanity check */
        if(nlm->nlmsg_pid != nchannel->pid) {
            LOG_ERR("NL message received for wrong PID: %d != %d", nlm->nlmsg_pid, nchannel->pid);
            return -1;
        }

        if(nchannel->reliable && nlm->nlmsg_flags & NLM_F_ACK) {
            /* ack the seq num */
            ack_seq_num(nchannel, nlm->nlmsg_seq);
        }

        switch (nlm->nlmsg_type) {
        case NLMSG_NOOP:
            break;
        case NLMSG_ERROR:
            nlmerr = (struct nlmsgerr *) NLMSG_DATA(nlm);
            if(nlmerr->error == 0) {
                LOG_DBG("NLMSG_ACK");
            } else {
                LOG_DBG("NLMSG_ERROR, error=%d type=%d\n",
                        nlmerr->error, nlmerr->msg.nlmsg_type);
            }
            break;
        case NLMSG_DONE:
            //LOG_DBG("NLMSG_DONE\n");
            break;
        case NLMSG_SERVAL:
            //TODO - ack and rpc request cache/resend?
            nchannel->base.callback.recv_message(nchannel->base.callback.target, NLMSG_DATA(nlm),
                    datalen - NLMSG_LENGTH(0));
            break;
        default:
            LOG_DBG("Unknown netlink message\n");
            break;
        }
    }
    return 0;
}

/* single-threaded/task - not threadsafe! */
static void netlink_recv_task(void* channel) {
    struct sv_netlink_message_channel* nchannel = (struct sv_netlink_message_channel *) channel;
    /* read from the socket until EWOULDBLOCK/EAGAIN, then reschedule */

    int ret = 1;
    socklen_t addrlen;
    addrlen = sizeof(struct sockaddr_nl);

    while (atomic_read(&nchannel->base.running) && ret) {
        //MSG_DONTWAIT
        ret = recvfrom(nchannel->base.sock, nchannel->base.buffer, nchannel->base.buffer_len, 0,
                (struct sockaddr *) &nchannel->peer, &addrlen);

        if(ret == -1) {
            if(errno == EAGAIN || errno == EWOULDBLOCK) {
                LOG_DBG("Netlink recv would block\n");
                //TODO yield/block
                task_block(nchannel->base.sock, FD_READ);
                continue;
            }

            LOG_ERR("recv error: %s\n", strerror(errno));
            atomic_set(&nchannel->base.running, 0);
            return;
        }

        netlink_recv(channel, nchannel->base.buffer, ret);
    }

    return;
}
