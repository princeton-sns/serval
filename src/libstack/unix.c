/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <libstack/ctrlmsg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include "init.h"
#include "debug.h"
#include "event.h"

int ctrlmsg_handle(struct ctrlmsg *cm);

#define BUFLEN 100

struct unix_handle {
	struct event_handler *eh;
	int sock;
	struct sockaddr_un peer;
	pthread_t thread;
	unsigned char buf[BUFLEN];
};

static int unix_handle_init(struct event_handler *eh)
{
	struct unix_handle *uh = (struct unix_handle *)eh->private;
	int ret;
        
        LOG_DBG("initializing SCAFFOLD unix control\n");

	memset(uh, 0, sizeof(*uh));
	
	uh->sock = socket(AF_UNIX, SOCK_DGRAM, 0);

	if (uh->sock == -1) {
		LOG_ERR("Scaffold unix socket failure: %s\n",
                        strerror(errno));
		goto error_sock;
	}

	uh->peer.sun_family = AF_UNIX;
	strcpy(uh->peer.sun_path, SCAFFOLD_SCAFD_CTRL_PATH);
	
	ret = bind(uh->sock, (struct sockaddr *)&uh->peer, 
		   sizeof(uh->peer));

	if (ret == -1) {
		LOG_ERR("bind failed: %s\n",
			strerror(errno));
		goto error_bind;
	}


	/* Now set the address to point to the stack */
	strcpy(uh->peer.sun_path, SCAFFOLD_STACK_CTRL_PATH);

	/* 
	   Use the connect call to see if there is a control
	   socket available. This means the userlevel Scaffold
	   daemon is running. Since we are not a STREAM socket
	   the connection will fail, but that is our cue that
	   Scaffold is running.
	*/
	ret = connect(uh->sock, (struct sockaddr *)&uh->peer, 
		      sizeof(uh->peer));

	if (ret == -1) {
		if (errno == ENOENT) {
			/* This probably means we are not running the
			 * user space version of the Scaffold stack,
			 * therefore unregister this handler and exit
			 * without error. */
			LOG_DBG("unix control not supported, disabling\n");
			event_unregister_handler(eh);
                        return 0;
		} else if (errno == ECONNREFUSED) {
			/* Success, daemon is running */
			LOG_DBG("connection refused\n");
			ret = 0;
		} else {
			LOG_ERR("connect unix error: %s\n", strerror(errno));
			goto error_connect;
		}
	}
out:
	return ret;
error_connect:
	unlink(SCAFFOLD_SCAFD_CTRL_PATH);
error_bind:
	close(uh->sock);
	uh->sock = -1;
error_sock:
	event_unregister_handler(eh);
	goto out;
}

static void unix_handle_destroy(struct event_handler *eh)
{
	struct unix_handle *uh = (struct unix_handle *)eh->private;
	if (uh->sock != -1) {
		close(uh->sock);
		unlink(SCAFFOLD_SCAFD_CTRL_PATH);
	}
}

static int unix_handle_event(struct event_handler *eh)
{
	struct unix_handle *uh = (struct unix_handle *)eh->private;
	struct ctrlmsg *cm;
	struct sockaddr_un from;
	socklen_t addr_len = 0;
	int ret;

	memset(uh->buf, 0, BUFLEN);
	memset(&from, 0, sizeof(from));

	ret = recvfrom(uh->sock, uh->buf, BUFLEN, MSG_DONTWAIT,
		       (struct sockaddr *)&from, &addr_len);

	if (ret == -1) {
		if (errno == EWOULDBLOCK) {
			return 0;
		} else {
			LOG_DBG("recvmsg error: %s\n",
				strerror(errno));
		}
		return ret;
	}

	cm = (struct ctrlmsg *)uh->buf;

	LOG_DBG("control message type=%u\n", cm->type);

	return ctrlmsg_handle(cm);
}

static int unix_getfd(struct event_handler *eh)
{
	struct unix_handle *uh = (struct unix_handle *)eh->private;
	return uh->sock;
}

static struct unix_handle uh;

static struct event_handler eh = {
	.name = "unix",
	.init = unix_handle_init,
	.cleanup = unix_handle_destroy,
	.getfd = unix_getfd,
	.handle_event = unix_handle_event,
	.private = (void *)&uh
};

__onload
void unix_init(void)
{
	event_register_handler(&eh);
}

__onexit
void unix_fini(void)
{
	event_unregister_handler(&eh);
}
