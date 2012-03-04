/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _CLIENT_MSG_H_
#define _CLIENT_MSG_H_

#include <serval/platform.h>
#include <netinet/serval.h>

typedef enum client_msg_type { 
	MSG_UNKNOWN = 0, 
	MSG_BIND_REQ, 
	MSG_BIND_RSP,
	MSG_CONNECT_REQ, 
	MSG_CONNECT_RSP,
	MSG_LISTEN_REQ, 
	MSG_LISTEN_RSP,
	MSG_ACCEPT_REQ, 
	MSG_ACCEPT_RSP,
	MSG_ACCEPT2_REQ, 
	MSG_ACCEPT2_RSP,
	MSG_SEND_REQ, 
	MSG_SEND_RSP,
	MSG_RECV_REQ, 
	MSG_RECV_RSP,
	MSG_CLOSE_REQ, 
	MSG_CLOSE_RSP,
	MSG_RECVMESG, 
	MSG_CLEAR_DATA, 
	MSG_HAVE_DATA
} client_msg_type_t;

extern unsigned int client_msg_lengths[];

#define MAX_CLIENT_MSG_TYPE (MSG_HAVE_DATA + 1)
#define CLIENT_MSG_VERSION 1

typedef unsigned char bool_t;

struct client_msg {
	unsigned char version;
	unsigned char type;
	uint16_t payload_length;
	unsigned char payload[0];
};

/* Generic response message */
struct client_msg_rsp {
        struct client_msg msghdr;
        uint8_t error;
};

#define CLIENT_MSG_HDR_LEN (sizeof(struct client_msg))

#define DEFINE_CLIENT_RESPONSE(name, type) \
        struct client_msg_rsp rsp =                                    \
                { { CLIENT_MSG_VERSION,                                \
                    type,                                              \
                    client_msg_lengths[type] - CLIENT_MSG_HDR_LEN },   \
                  0 }

/* Specific messages: */

/* Bind messages */
struct client_msg_bind_req {
	struct client_msg msghdr;
	uint8_t flags;
	uint8_t prefix;
	struct service_id srvid;
} __attribute__((packed));

#define CLIENT_MSG_BIND_REQ_LEN (sizeof(struct client_msg_bind_req))

struct client_msg_bind_rsp {
	struct client_msg msghdr;
	struct service_id srvid;
	uint8_t error;
} __attribute__((packed));

#define CLIENT_MSG_BIND_RSP_LEN (sizeof(struct client_msg_bind_rsp))

/* Connect messages */
struct client_msg_connect_req {
	struct client_msg msghdr;
	struct service_id srvid;
        bool_t nonblock;
        uint16_t flags;
} __attribute__((packed));

#define CLIENT_MSG_CONNECT_REQ_LEN (sizeof(struct client_msg_connect_req))

struct client_msg_connect_rsp {
	struct client_msg msghdr;
	struct service_id srvid;
	uint8_t error;
} __attribute__((packed));

#define CLIENT_MSG_CONNECT_RSP_LEN (sizeof(struct client_msg_connect_rsp))

/* Listen messages */
struct client_msg_listen_req {
	struct client_msg msghdr;
	bool_t use_first;       
	struct service_id srvid;
	uint16_t backlog;
} __attribute__((packed));

#define CLIENT_MSG_LISTEN_REQ_LEN (sizeof(struct client_msg_listen_req))

struct client_msg_listen_rsp {
	struct client_msg msghdr;
	uint8_t error;
} __attribute__((packed));

#define CLIENT_MSG_LISTEN_RSP_LEN (sizeof(struct client_msg_listen_rsp))

/* Accept messages */
struct client_msg_accept_req {
	struct client_msg msghdr;
        bool_t nonblock;
} __attribute__((packed));

#define CLIENT_MSG_ACCEPT_REQ_LEN (sizeof(struct client_msg_accept_req))

struct client_msg_accept_rsp {
	struct client_msg msghdr;
        struct service_id local_srvid;
        struct service_id peer_srvid;
        struct flow_id flowid;
	uint8_t error;
} __attribute__((packed));

#define CLIENT_MSG_ACCEPT_RSP_LEN (sizeof(struct client_msg_accept_rsp))

/* Accept2 messages */
struct client_msg_accept2_req {
	struct client_msg msghdr;
	struct service_id srvid;
        struct flow_id flowid;
        bool_t nonblock;
} __attribute__((packed));

#define CLIENT_MSG_ACCEPT2_REQ_LEN (sizeof(struct client_msg_accept2_req))

struct client_msg_accept2_rsp {
	struct client_msg msghdr;
	uint8_t error;
} __attribute__((packed));

#define CLIENT_MSG_ACCEPT2_RSP_LEN (sizeof(struct client_msg_accept2_rsp))

/* Send messages */
struct client_msg_send_req {
	struct client_msg msghdr;
        bool_t non_blocking;
        struct service_id srvid;
        uint32_t ipaddr;
        uint16_t data_len;
        int flags;
        unsigned char data[0];
} __attribute__((packed));

#define CLIENT_MSG_SEND_REQ_LEN (sizeof(struct client_msg_send_req))

struct client_msg_send_rsp {
	struct client_msg msghdr;
	uint8_t error;
} __attribute__((packed));

#define CLIENT_MSG_SEND_RSP_LEN (sizeof(struct client_msg_send_rsp))

/* Receive messages */
struct client_msg_recv_req {
	struct client_msg msghdr;
        uint16_t data_len;
        int flags;
} __attribute__((packed));

#define CLIENT_MSG_RECV_REQ_LEN (sizeof(struct client_msg_recv_req))

struct client_msg_recv_rsp {
	struct client_msg msghdr;
        struct service_id srvid;
        uint32_t ipaddr;
        uint16_t data_len;
        int flags;
	uint8_t error;
        unsigned char data[0];
} __attribute__((packed));

#define CLIENT_MSG_RECV_RSP_LEN (sizeof(struct client_msg_recv_rsp))

/* Recvmsg */
struct client_msg_recvmsg {
	struct client_msg msghdr;
} __attribute__((packed));

#define CLIENT_MSG_RECVMSG_LEN (sizeof(struct client_msg_recvmsg))

/* Clear/Have data messages */
struct client_msg_clear_data {
	struct client_msg msghdr;
} __attribute__((packed));

#define CLIENT_MSG_CLEAR_DATA_LEN (sizeof(struct client_msg_clear_data))

struct client_msg_have_data {
	struct client_msg msghdr;
} __attribute__((packed));

#define CLIENT_MSG_HAVE_DATA_LEN (sizeof(struct client_msg_have_data))

/* Close messages */
struct client_msg_close_req {
	struct client_msg msghdr;
} __attribute__((packed));

#define CLIENT_MSG_CLOSE_REQ_LEN (sizeof(struct client_msg_close_req))

struct client_msg_close_rsp {
	struct client_msg msghdr;
	uint8_t error;
} __attribute__((packed));

#define CLIENT_MSG_CLOSE_RSP_LEN (sizeof(struct client_msg_close_rsp))

int client_msg_print(struct client_msg *msg, char *buf, int size);
void client_msg_free(struct client_msg *msg);
const char *client_msg_to_typestr(struct client_msg *msg);
const char *client_client_msg_type_to_str(client_msg_type_t type);
int client_msg_read(int sock, struct client_msg **msg);
int client_msg_write(int sock, struct client_msg *msg);
void client_msg_hdr_init(struct client_msg *msg, client_msg_type_t type);

#endif /* _CLIENT_MSG_H_ */
