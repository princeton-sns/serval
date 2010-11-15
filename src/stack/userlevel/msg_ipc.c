/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <scaffold/debug.h>
#include "msg_ipc.h"

static const char *msg_ipc_str[] = {
	"MSG_UNKNOWN",
	"MSG_BIND_REQ", 
	"MSG_BIND_RSP",
	"MSG_CONNECT_REQ", 
	"MSG_CONNECT_RSP",
	"MSG_LISTEN_REQ", 
	"MSG_LISTEN_RSP",
	"MSG_ACCEPT_REQ", 
	"MSG_ACCEPT_RSP",
	"MSG_ACCEPT2_REQ", 
	"MSG_ACCEPT2_RSP",
	"MSG_SEND_REQ", 
	"MSG_SEND_RSP",
	"MSG_RECV_REQ", 
	"MSG_RECV_RSP",
	"MSG_MIG_REQ", 
	"MSG_MIG_RSP",
	"MSG_RECONN_REQ", 
	"MSG_RECONN_RSP",
	"MSG_CLOSE_REQ", 
	"MSG_CLOSE_RSP",
	"MSG_RECVMESG", 
	"MSG_CLEAR_DATA", 
	"MSG_HAVE_DATA",
	NULL
};

static unsigned int msg_ipc_lengths[] = {
	MSG_IPC_HDR_LEN,
	MSG_IPC_BIND_REQ_LEN,
	MSG_IPC_BIND_RSP_LEN,
	MSG_IPC_CONNECT_REQ_LEN,
	MSG_IPC_CONNECT_RSP_LEN,
	MSG_IPC_LISTEN_REQ_LEN,
	MSG_IPC_LISTEN_RSP_LEN,
	MSG_IPC_ACCEPT_REQ_LEN,
	MSG_IPC_ACCEPT_RSP_LEN,
	MSG_IPC_ACCEPT2_REQ_LEN,
	MSG_IPC_ACCEPT2_RSP_LEN,
	MSG_IPC_SEND_REQ_LEN,
	MSG_IPC_SEND_RSP_LEN,
	MSG_IPC_RECV_REQ_LEN,
	MSG_IPC_RECV_RSP_LEN,
	MSG_IPC_MIG_REQ_LEN,
	MSG_IPC_MIG_RSP_LEN,
	MSG_IPC_RECONN_REQ_LEN,
	MSG_IPC_RECONN_RSP_LEN,
	MSG_IPC_CLOSE_REQ_LEN,
	MSG_IPC_CLOSE_RSP_LEN,
	MSG_IPC_RECVMSG_LEN,
	MSG_IPC_CLEAR_DATA_LEN,
	MSG_IPC_HAVE_DATA_LEN
};

const char* msg_ipc_type_to_str(msg_type_t type)
{
	return msg_ipc_str[type];
}

const char *msg_ipc_to_typestr(struct msg_ipc *msg)
{
	if (msg->type < 0 || msg->type >= MAX_MSG_TYPE)
		return msg_ipc_str[MSG_UNKNOWN];

	return msg_ipc_str[msg->type];
}

int msg_ipc_print(struct msg_ipc *msg, char *buf, int size)
{
	if (!msg || !buf)
		return -1;

	return snprintf(buf, size, "type=%s payload_length=%u\n",
			msg_ipc_to_typestr(msg), msg->payload_length);
}

void msg_ipc_free(struct msg_ipc *msg)
{
	if (msg)
		free(msg);
}

int msg_ipc_read(int sock, struct msg_ipc **msg)
{
	struct msg_ipc *msg_tmp;
	ssize_t len;
	
	msg_tmp = (struct msg_ipc *)malloc(MSG_IPC_HDR_LEN);

	if (!msg_tmp)
		return -1;

	len = recv(sock, msg_tmp, MSG_IPC_HDR_LEN, 0);

	if (len == -1) {
		LOG_ERR("Message read error : %s\n", strerror(errno));
		free(msg_tmp);
		return -1;
	} else if (len == 0) {
		return 0;
	} else if (len < MSG_IPC_HDR_LEN) {
		LOG_ERR("Message too short\n");
		free(msg_tmp);
		return -1;
	}
	
	LOG_DBG("Message %s payload_length=%u\n", 
		msg_ipc_to_typestr(msg_tmp), msg_tmp->payload_length);

	len = msg_tmp->payload_length + MSG_IPC_HDR_LEN;

	if (len != msg_ipc_lengths[msg_tmp->type]) {
		LOG_ERR("Message %s does not match message type length (%zd/%u)\n", 
			msg_ipc_to_typestr(msg_tmp), len, msg_ipc_lengths[msg_tmp->type]);
		free(msg_tmp);
		return -1;
	}
	/* Read payload */
	*msg = (struct msg_ipc *)realloc(msg_tmp, MSG_IPC_HDR_LEN + msg_tmp->payload_length);

	if (!*msg) {
		free(msg_tmp);
		LOG_ERR("Could not allocate memory for payload\n");
		return -1;
	}

	len = recv(sock, (*msg)->payload, (*msg)->payload_length, 0);

	if (len == -1) {
		LOG_ERR("Message payload read error : %s\n", strerror(errno));
		free(*msg);
		return -1;
	} else if (len < (*msg)->payload_length) {
		LOG_ERR("Message paylaod too short\n");
		free(*msg);
		return -1;
	}
	
	return MSG_IPC_HDR_LEN + (*msg)->payload_length;
}

int msg_ipc_write(int sock, struct msg_ipc *msg)
{
	return send(sock, msg, MSG_IPC_HDR_LEN + msg->payload_length, MSG_DONTWAIT);
}

void msg_ipc_hdr_init(struct msg_ipc *msg, msg_type_t type)
{
	msg->version = MSG_IPC_VERSION;
	msg->type = type;
	msg->payload_length = msg_ipc_lengths[msg->type] - MSG_IPC_HDR_LEN;
	memset(msg->payload, 0, msg->payload_length);
}
