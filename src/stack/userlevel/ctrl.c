/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <serval/debug.h>
#include <libstack/ctrlmsg.h>
#include <ctrl.h>

static int ctrl_sock = -1;
struct sockaddr_un unaddr;

#define RCV_BUFSIZE 100
static unsigned char buf[RCV_BUFSIZE];

extern ctrlmsg_handler_t handlers[];

int ctrl_recvmsg(void)
{
        struct iovec iov = { buf, RCV_BUFSIZE };
	struct msghdr mh = { NULL, 0, &iov, 1, NULL, 0, 0 };
	struct ctrlmsg *cm;
	ssize_t nbytes;
        int ret = 0;

	nbytes = recvmsg(ctrl_sock, &mh, MSG_DONTWAIT);

	if (nbytes == -1) {
		switch (errno) {
		case EWOULDBLOCK:
			break;
		default:
			LOG_ERR("recvfrom error: %s\n",
				strerror(errno));
		}
		return -1;
	}

	if (mh.msg_iovlen == 0) {
		LOG_ERR("control message missing\n");
		return -1;
	} 

	cm = (struct ctrlmsg *)mh.msg_iov[0].iov_base;
        
        if (cm->type >= CTRLMSG_TYPE_UNKNOWN) {
                LOG_ERR("No handler for message type %u\n",
                        cm->type);
                ret = -1;
        } else {
                ret = handlers[cm->type](cm);
                
                if (ret == -1) {
                        LOG_ERR("handler failure for message type %u\n",
                                cm->type);
                }
        }
	return ret;
}

int ctrl_sendmsg(struct ctrlmsg *msg, int mask)
{
	struct msghdr *mh = (struct msghdr *)buf;
	struct iovec iov = { msg, msg->len };
	int ret;
	
	memset(mh, 0, sizeof(*mh));
	mh->msg_name = &unaddr;
	mh->msg_namelen = sizeof(unaddr);
	mh->msg_iov = &iov;
	mh->msg_iovlen = 1;
	
	ret = sendmsg(ctrl_sock, mh, 0);

	if (ret == -1) {
		LOG_ERR("sendmsg failure: %s\n", strerror(errno));
	} else {
		LOG_DBG("sent %d bytes\n", ret);
                ret = 0;
	}

	return ret;
}

int ctrl_getfd(void)
{
	return ctrl_sock;
}

int ctrl_init(void)
{
	int ret;
	
	ctrl_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	
	if (ctrl_sock == -1) {
		LOG_ERR("socket failure: %s\n", strerror(errno));
		return -1;
	}
	
	memset(&unaddr, 0, sizeof(unaddr));
	unaddr.sun_family = AF_UNIX;
	strcpy(unaddr.sun_path, SERVAL_STACK_CTRL_PATH);
	
	ret = bind(ctrl_sock, 
		   (struct sockaddr *)&unaddr, sizeof(unaddr));

	if (ret == -1) {
		LOG_ERR("bind failure: %s\n", strerror(errno));
		goto out_close_sock;
	}
	
	ret = chmod(SERVAL_STACK_CTRL_PATH, S_IRWXU|S_IRWXG|S_IRWXO);

	if (ret == -1) {
		LOG_ERR("chmod file %s : %s\n",
			SERVAL_STACK_CTRL_PATH, strerror(errno));
		goto out_unbind;
	}
	/* Now set the address to point to scafd */
	strcpy(unaddr.sun_path, SERVAL_SCAFD_CTRL_PATH);
out:
	return ret;
out_unbind:
	unlink(SERVAL_STACK_CTRL_PATH);
out_close_sock:
	close(ctrl_sock);
	goto out;
}

void ctrl_fini(void)
{
	if (ctrl_sock != -1)
		close(ctrl_sock);
	
	unlink(SERVAL_STACK_CTRL_PATH);
}
