/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#define _GNU_SOURCE 1
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <serval/debug.h>
#include <serval/ctrlmsg.h>
#include <common/hashtable.h>
#include <common/platform.h>
#include <ctrl.h>
#include "client.h"

#if defined (OS_MACOSX)
#include <sys/ucred.h>
#endif

static int ctrl_sock = -1;
struct sockaddr_un unaddr;

#define RCV_BUFSIZE 2048
static unsigned char rbuf[RCV_BUFSIZE];

extern ctrlmsg_handler_t handlers[];

struct hashtable ctrl_clients;

struct ctrl_client {
        hashelm_t he;
        struct sockaddr_un un;
};

static void ctrl_client_free(hashelm_t *elm)
{
        struct ctrl_client *cc = container_of(elm, struct ctrl_client, he);
        LOG_DBG("Freeing ctrl client %s\n",
                cc->un.sun_path);
        free(cc);
}

static inline unsigned int ctrl_client_hashfn(const void *key)
{
        struct sockaddr_un *un = (struct sockaddr_un *)key;
        unsigned int hash = full_name_hash(un->sun_path, strlen(un->sun_path));
        return hash;
}

static inline int ctrl_client_equalfn(const hashelm_t *e, const void *key)
{
        struct sockaddr_un *un1 = &container_of(e, struct ctrl_client, he)->un;
        struct sockaddr_un *un2 = (struct sockaddr_un *)key;
        return strcmp(un1->sun_path, un2->sun_path) == 0;
}

static struct ctrl_client *ctrl_client_new(struct sockaddr_un *un)
{
        struct ctrl_client *cc;

        cc = malloc(sizeof(*cc));

        if (!cc)
                return NULL;

        memset(cc, 0, sizeof(*cc));
        hashelm_init(&cc->he, ctrl_client_hashfn, 
                     ctrl_client_equalfn, ctrl_client_free);

        memcpy(&cc->un, un, sizeof(*un));
        cc->he.keylen = sizeof(cc->un);
        cc->he.key = &cc->un;

        return cc;
}

#define CMSGBUF_LEN 512

int ctrl_recvmsg(void)
{
        int peer = 0;
        struct sockaddr_un un;
        struct cmsghdr *cmsg;
        unsigned char cmsgbuf[CMSGBUF_LEN];
        struct iovec iov = { rbuf, RCV_BUFSIZE };
	struct msghdr mh = { &un, sizeof(un), &iov, 1,
                             cmsgbuf, CMSGBUF_LEN, 0 };
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

        /* Parse ancillary control information */
        cmsg = CMSG_FIRSTHDR(&mh);
        
        while (cmsg) {
                if (cmsg->cmsg_level == SOL_SOCKET) {
                        switch (cmsg->cmsg_type) {
                        case SCM_CREDENTIALS:
                                if (cmsg->cmsg_len == CMSG_LEN(sizeof(ucred_t))) {
                                        ucred_t *cred = (ucred_t *)CMSG_DATA(cmsg);
                                        peer = cred->ucred_pid;
                                }
                                break;
                        default:
                                LOG_DBG("Unknown ancillary data in control msg\n");
                                break;
                        }
                }
                cmsg = CMSG_NXTHDR(&mh, cmsg);
        }
                
	if (mh.msg_iovlen == 0) {
		LOG_ERR("control message missing\n");
		return -1;
	}

	cm = (struct ctrlmsg *)mh.msg_iov[0].iov_base;

	LOG_DBG("Received ctrl msg(%u) of %zd bytes\n", cm->type, nbytes);

        if (cm->type >= _CTRLMSG_TYPE_MAX) {
                LOG_ERR("No handler for message type %u\n",
                        cm->type);
                ret = -1;
        } else {
                struct hashelm *elm;
                
                elm = hashtable_lookup(&ctrl_clients, &un,
                                       ctrl_client_hashfn);
                if (!elm) {
                        struct ctrl_client *cc = ctrl_client_new(&un);
                        
                        if (cc) {
                                hashelm_hash(&ctrl_clients, &cc->he, &un);
                                LOG_DBG("Adding new ctrl client at %s\n",
                                        un.sun_path);
                                hashelm_put(&cc->he);
                        }
                } else {
                        hashelm_put(elm);
                }
                
                ret = handlers[cm->type](cm, peer);

                if (ret == -1) {
                        LOG_ERR("handler failure for message type %u\n",
                                cm->type);
                }
        }
	return ret;
}

static void ctrl_send_to_all(struct hashelm *elm, void *data)
{
        struct ctrl_client *cc = container_of(elm, struct ctrl_client, he);
        struct ctrlmsg *msg = (struct ctrlmsg *)data;
        int ret;
        
        ret = sendto(ctrl_sock, msg, msg->len, 0,
                     (struct sockaddr *)&cc->un, sizeof(cc->un));

	if (ret == -1) {
		LOG_DBG("Removing ctrl client %s\n",
                        cc->un.sun_path);
                __hashelm_unhash(&ctrl_clients, elm);
	}
}

int ctrl_sendmsg(struct ctrlmsg *msg, int peer, int mask)
{        
        hashtable_for_each(&ctrl_clients, ctrl_send_to_all, msg);
        return 0;
}

int ctrl_getfd(void)
{
	return ctrl_sock;
}

int ctrl_init(void)
{
	int ret;
        int on = 1;

        hashtable_init(&ctrl_clients, 32);

	ctrl_sock = socket(AF_UNIX, SOCK_DGRAM, 0);

	if (ctrl_sock == -1) {
		LOG_ERR("socket failure: %s\n", strerror(errno));
		return -1;
	}

        ret = setsockopt(ctrl_sock, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));

        if (ret == -1) {
                LOG_ERR("setsockopt: %s\n", strerror(errno));
                goto out_close_sock;
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

	ret = chmod(unaddr.sun_path, S_IRWXU|S_IRWXG|S_IRWXO);

	if (ret == -1) {
		LOG_ERR("chmod file %s : %s\n",
			unaddr.sun_path, strerror(errno));
		goto out_unbind;
	}
out:
	return ret;
out_unbind:
	unlink(unaddr.sun_path);
out_close_sock:
	close(ctrl_sock);
	goto out;
}

void ctrl_fini(void)
{
	if (ctrl_sock != -1)
		close(ctrl_sock);

        unlink(SERVAL_STACK_CTRL_PATH);

        hashtable_fini(&ctrl_clients);
}
