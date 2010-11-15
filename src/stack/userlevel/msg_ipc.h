/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _MSG_IPC_H_
#define _MSG_IPC_H_

#include <scaffold/platform.h>
#include <netinet/scaffold.h>

typedef enum msg_type { 
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
	MSG_MIG_REQ, 
	MSG_MIG_RSP,
	MSG_RECONN_REQ, 
	MSG_RECONN_RSP,
	MSG_CLOSE_REQ, 
	MSG_CLOSE_RSP,
	MSG_RECVMESG, 
	MSG_CLEAR_DATA, 
	MSG_HAVE_DATA
} msg_type_t;

#define MAX_MSG_TYPE (MSG_HAVE_DATA + 1)

#define MSG_IPC_VERSION 1

typedef unsigned char bool_t;

struct msg_ipc {
	unsigned char version;
	unsigned char type;
	uint16_t payload_length;
	unsigned char payload[0];
};

#define MSG_IPC_HDR_LEN (sizeof(struct msg_ipc))

/* Bind messages */
struct msg_ipc_bind_req {
	struct msg_ipc msghdr;
	struct service_id srvid;
} __attribute__((packed));

#define MSG_IPC_BIND_REQ_LEN (sizeof(struct msg_ipc_bind_req))

struct msg_ipc_bind_rsp {
	struct msg_ipc msghdr;
	struct service_id srvid;
	uint8_t error;
} __attribute__((packed));

#define MSG_IPC_BIND_RSP_LEN (sizeof(struct msg_ipc_bind_rsp))

/* Connect messages */
struct msg_ipc_connect_req {
	struct msg_ipc msghdr;
	struct service_id srvid;
} __attribute__((packed));

#define MSG_IPC_CONNECT_REQ_LEN (sizeof(struct msg_ipc_connect_req))

struct msg_ipc_connect_rsp {
	struct msg_ipc msghdr;
	struct service_id srvid;
	uint8_t error;
} __attribute__((packed));

#define MSG_IPC_CONNECT_RSP_LEN (sizeof(struct msg_ipc_connect_rsp))

/* Listen messages */
struct msg_ipc_listen_req {
	struct msg_ipc msghdr;
	bool_t use_first;       
	struct service_id srvid;
	uint16_t backlog;
} __attribute__((packed));

#define MSG_IPC_LISTEN_REQ_LEN (sizeof(struct msg_ipc_listen_req))

struct msg_ipc_listen_rsp {
	struct msg_ipc msghdr;
	struct service_id srvid;
	uint8_t error;
} __attribute__((packed));

#define MSG_IPC_LISTEN_RSP_LEN (sizeof(struct msg_ipc_listen_rsp))

/* Accept messages */
struct msg_ipc_accept_req {
	struct msg_ipc msghdr;
	bool_t use_first;       
	struct service_id srvid;
	uint16_t backlog;
} __attribute__((packed));

#define MSG_IPC_ACCEPT_REQ_LEN (sizeof(struct msg_ipc_accept_req))

struct msg_ipc_accept_rsp {
	struct msg_ipc msghdr;
	struct service_id srvid;
	uint8_t error;
} __attribute__((packed));

#define MSG_IPC_ACCEPT_RSP_LEN (sizeof(struct msg_ipc_accept_rsp))

/* Accept2 messages */
struct msg_ipc_accept2_req {
	struct msg_ipc msghdr;
} __attribute__((packed));

#define MSG_IPC_ACCEPT2_REQ_LEN (sizeof(struct msg_ipc_accept2_req))

struct msg_ipc_accept2_rsp {
	struct msg_ipc msghdr;
	uint8_t error;
} __attribute__((packed));

#define MSG_IPC_ACCEPT2_RSP_LEN (sizeof(struct msg_ipc_accept2_rsp))

/* Send messages */
struct msg_ipc_send_req {
	struct msg_ipc msghdr;
} __attribute__((packed));

#define MSG_IPC_SEND_REQ_LEN (sizeof(struct msg_ipc_send_req))

struct msg_ipc_send_rsp {
	struct msg_ipc msghdr;
	uint8_t error;
} __attribute__((packed));

#define MSG_IPC_SEND_RSP_LEN (sizeof(struct msg_ipc_send_rsp))

/* Receive messages */
struct msg_ipc_recv_req {
	struct msg_ipc msghdr;
} __attribute__((packed));

#define MSG_IPC_RECV_REQ_LEN (sizeof(struct msg_ipc_recv_req))

struct msg_ipc_recv_rsp {
	struct msg_ipc msghdr;
	uint8_t error;
} __attribute__((packed));;

#define MSG_IPC_RECV_RSP_LEN (sizeof(struct msg_ipc_recv_rsp))

/* Migrate messages */
struct msg_ipc_mig_req {
	struct msg_ipc msghdr;
} __attribute__((packed));

#define MSG_IPC_MIG_REQ_LEN (sizeof(struct msg_ipc_mig_req))

struct msg_ipc_mig_rsp {
	struct msg_ipc msghdr;
	uint8_t error;
} __attribute__((packed));

#define MSG_IPC_MIG_RSP_LEN (sizeof(struct msg_ipc_mig_rsp))

/* Reconnect messages */
struct msg_ipc_reconn_req {
	struct msg_ipc msghdr;
} __attribute__((packed));

#define MSG_IPC_RECONN_REQ_LEN (sizeof(struct msg_ipc_reconn_req))

struct msg_ipc_reconn_rsp {
	struct msg_ipc msghdr;
	uint8_t error;
} __attribute__((packed));

#define MSG_IPC_RECONN_RSP_LEN (sizeof(struct msg_ipc_reconn_rsp))

/* Recvmsg */
struct msg_ipc_recvmsg {
	struct msg_ipc msghdr;
} __attribute__((packed));

#define MSG_IPC_RECVMSG_LEN (sizeof(struct msg_ipc_recvmsg))

/* Clear/Have data messages */
struct msg_ipc_clear_data {
	struct msg_ipc msghdr;
} __attribute__((packed));

#define MSG_IPC_CLEAR_DATA_LEN (sizeof(struct msg_ipc_clear_data))

struct msg_ipc_have_data {
	struct msg_ipc msghdr;
} __attribute__((packed));

#define MSG_IPC_HAVE_DATA_LEN (sizeof(struct msg_ipc_have_data))

/* Close messages */
struct msg_ipc_close_req {
	struct msg_ipc msghdr;
} __attribute__((packed));

#define MSG_IPC_CLOSE_REQ_LEN (sizeof(struct msg_ipc_close_req))

struct msg_ipc_close_rsp {
	struct msg_ipc msghdr;
	uint8_t error;
} __attribute__((packed));

#define MSG_IPC_CLOSE_RSP_LEN (sizeof(struct msg_ipc_close_rsp))

int msg_ipc_print(struct msg_ipc *msg, char *buf, int size);
void msg_ipc_free(struct msg_ipc *msg);
const char *msg_ipc_to_typestr(struct msg_ipc *msg);
const char *msg_ipc_type_to_str(msg_type_t type);
int msg_ipc_read(int sock, struct msg_ipc **msg);
int msg_ipc_write(int sock, struct msg_ipc *msg);
void msg_ipc_hdr_init(struct msg_ipc *msg, msg_type_t type);

#endif /* _MSG_IPC_H_ */
