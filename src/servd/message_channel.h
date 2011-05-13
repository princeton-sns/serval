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

    int (*recv_message)(void* target, const void* message, size_t length);
} message_channel_callback;

struct sv_message_channel {
    /*message_channel_callback callback;*/
};

struct sv_message_channel_interface {
    int (*initialize)(void* target);
    void (*start)(void* target);
    void (*stop)(void* target);
    int (*finalize)(void* target);

    const struct sockaddr* (*get_local_address)(void* target, int* len);
    /* primarily meant for serval message channels - change the peer address */
    void (*set_peer_address)(void* target, struct sockaddr* addr, size_t len);
    const struct sockaddr* (*get_peer_address)(void* target, int* len);
    int (*get_max_message_size)(void* target);

    /* for request/response callback handling */
    int (*register_callback)(void* target, message_channel_callback* cb);
    int (*unregister_callback)(void* target, message_channel_callback* cb);
    int (*get_callback_count)(void* target);

    int (*send_message)(void* target, void* message, size_t length);
    int (*send_message_iov)(void* target, struct iovec* iov, size_t veclen, size_t length);
    /* for direct message - local loop - receipt and debug */
    int (*recv_message)(void* target, const void* message, size_t length);
};

/* perhaps this should just have direct function pointer references
 * though, it would cost extra space vs. the single pointer to a staticly
 * defined interface struct.
 * caller/owner is responsible for allocating and destroying this wrapper struct
 * including the target?
 */
typedef struct {
    //atomic_t ref_count;
    void* target;
    struct sv_message_channel_interface* interface;
} message_channel;

//int message_channel_incref(message_channel* channel);
//int message_channel_decref(message_channel* channel);


#endif /* MESSAGE_CHANNEL_H_ */
