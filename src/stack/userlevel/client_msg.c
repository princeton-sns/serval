/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <scaffold/debug.h>
#include <userlevel/client_msg.h>

static const char *client_msg_str[] = {
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

unsigned int client_msg_lengths[] = {
	CLIENT_MSG_HDR_LEN,
	CLIENT_MSG_BIND_REQ_LEN,
	CLIENT_MSG_BIND_RSP_LEN,
	CLIENT_MSG_CONNECT_REQ_LEN,
	CLIENT_MSG_CONNECT_RSP_LEN,
	CLIENT_MSG_LISTEN_REQ_LEN,
	CLIENT_MSG_LISTEN_RSP_LEN,
	CLIENT_MSG_ACCEPT_REQ_LEN,
	CLIENT_MSG_ACCEPT_RSP_LEN,
	CLIENT_MSG_ACCEPT2_REQ_LEN,
	CLIENT_MSG_ACCEPT2_RSP_LEN,
	CLIENT_MSG_SEND_REQ_LEN,
	CLIENT_MSG_SEND_RSP_LEN,
	CLIENT_MSG_RECV_REQ_LEN,
	CLIENT_MSG_RECV_RSP_LEN,
	CLIENT_MSG_MIG_REQ_LEN,
	CLIENT_MSG_MIG_RSP_LEN,
	CLIENT_MSG_RECONN_REQ_LEN,
	CLIENT_MSG_RECONN_RSP_LEN,
	CLIENT_MSG_CLOSE_REQ_LEN,
	CLIENT_MSG_CLOSE_RSP_LEN,
	CLIENT_MSG_RECVMSG_LEN,
	CLIENT_MSG_CLEAR_DATA_LEN,
	CLIENT_MSG_HAVE_DATA_LEN
};

const char* client_msg_type_to_str(client_msg_type_t type)
{
	return client_msg_str[type];
}

const char *client_msg_to_typestr(struct client_msg *msg)
{
	if (msg->type >= MAX_CLIENT_MSG_TYPE)
		return client_msg_str[MSG_UNKNOWN];

	return client_msg_str[msg->type];
}

int client_msg_print(struct client_msg *msg, char *buf, int size)
{
	if (!msg || !buf)
		return -1;

	return snprintf(buf, size, "type=%s payload_length=%u\n",
			client_msg_to_typestr(msg), msg->payload_length);
}

void client_msg_free(struct client_msg *msg)
{
	if (msg)
		free(msg);
}

int client_msg_read(int sock, struct client_msg **msg)
{
	struct client_msg *msg_tmp;
	ssize_t len;
	unsigned int msg_len = 0;

	msg_tmp = (struct client_msg *)malloc(CLIENT_MSG_HDR_LEN);

	if (!msg_tmp)
		return -1;

	len = recv(sock, msg_tmp, CLIENT_MSG_HDR_LEN, 0);

	if (len == -1) {
		LOG_ERR("Message read error : %s\n", strerror(errno));
		free(msg_tmp);
		return -1;
	} else if (len == 0) {
                free(msg_tmp);
		return 0;
	} else if (len < (ssize_t)CLIENT_MSG_HDR_LEN) {
		LOG_ERR("Message too short\n");
		free(msg_tmp);
		return -1;
	}
	
	LOG_DBG("%s payload_length=%u\n", 
		client_msg_to_typestr(msg_tmp), msg_tmp->payload_length);
        
	msg_len = msg_tmp->payload_length + CLIENT_MSG_HDR_LEN;

	if (msg_len < client_msg_lengths[msg_tmp->type]) {
		LOG_ERR("%s bad length (got:%zd expected:>%u)\n", 
			client_msg_to_typestr(msg_tmp), msg_len, 
                        client_msg_lengths[msg_tmp->type]);
		free(msg_tmp);
		return -1;
	}
	/* Read payload */
	*msg = (struct client_msg *)realloc(msg_tmp, 
                                            CLIENT_MSG_HDR_LEN + 
                                            msg_tmp->payload_length);

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
	
	return CLIENT_MSG_HDR_LEN + (*msg)->payload_length;
}

int client_msg_write(int sock, struct client_msg *msg)
{
	int ret = send(sock, msg, CLIENT_MSG_HDR_LEN + 
                       msg->payload_length, MSG_DONTWAIT);

        if (ret == -1) {
                switch (errno) {
                case ECONNRESET:
                case ENOTCONN:
                case EPIPE:
                        /* Client probably closed */
                        ret = 0;
                        break;
                case EWOULDBLOCK:
                default:
                        LOG_ERR("write error: %s\n", strerror(errno));
                }
        }
        return ret;
}

void client_msg_hdr_init(struct client_msg *msg, client_msg_type_t type)
{
	msg->version = CLIENT_MSG_VERSION;
	msg->type = type;
	msg->payload_length = client_msg_lengths[msg->type] - CLIENT_MSG_HDR_LEN;
	memset(msg->payload, 0, msg->payload_length);
}
