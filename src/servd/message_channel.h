/*
 * message_channel.h
 *
 *  Created on: Feb 11, 2011
 *      Author: daveds
 */

#ifndef MESSAGE_CHANNEL_H_
#define MESSAGE_CHANNEL_H_

#include "netinet/serval.h"
#include "libstack/resolver_protocol.h"
#include "service_types.h"
#include <sys/socket.h>

#define MAX_MESSAGE_RETRIES 10

typedef struct sv_message_channel_callback {
    void* target;
    int (*recv_message)(struct sv_message_channel_callback* cb, const void* message, size_t length);
} message_channel_callback;

struct sv_message_channel {
    enum component_state state;
};
struct sv_message_channel_interface;
typedef struct {
    //atomic_t ref_count;
    struct sv_message_channel channel;
    struct sv_message_channel_interface* interface;
} message_channel;

struct sv_message_channel_interface {
    int (*initialize)(message_channel* channel);
    void (*start)(message_channel* channel);
    void (*stop)(message_channel* channel);
    int (*finalize)(message_channel* channel);

    const struct sockaddr* (*get_local_address)(message_channel* channel, int* len);
    /* primarily meant for serval message channels - change the peer address */
    void (*set_peer_address)(message_channel* channel, struct sockaddr* addr, size_t len);
    const struct sockaddr* (*get_peer_address)(message_channel* channel, int* len);
    int (*get_max_message_size)(message_channel* channel);

    /* for request/response callback handling */
    int (*register_callback)(message_channel* channel, message_channel_callback* cb);
    int (*unregister_callback)(message_channel* channel, message_channel_callback* cb);
    int (*get_callback_count)(message_channel* channel);

    int (*send_message)(message_channel* channel, void* message, size_t length);
    int (*send_message_iov)(message_channel* channel, struct iovec* iov, size_t veclen, size_t length);
    /* for direct message - local loop - receipt and debug */
    int (*recv_message)(message_channel* channel, const void* message, size_t length);
};


//int message_channel_incref(message_channel* channel);
//int message_channel_decref(message_channel* channel);


#endif /* MESSAGE_CHANNEL_H_ */
