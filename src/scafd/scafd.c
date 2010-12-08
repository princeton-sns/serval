/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h> 
#include <sys/select.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <signal.h>
#include <libstack/stack.h>
#include <libscaffold/scaffold.h>
#include <netinet/scaffold.h>
#include <scaffold/platform.h>
#include "debug.h"
#include "rtnl.h"

static int ctrlsock = -1; /* socket to communicate with controller */
static int native = 0; /* Whether the socket is native or libscaffold */

static int should_exit = 0;
static int p[2] = { -1, -1 };
struct sockaddr_sf ctrlid;

static void signal_handler(int sig)
{
        ssize_t ret;
        char q = 'q';

	should_exit = 1;
        ret = write(p[1], &q, 1);
}

static ssize_t scafd_sendto(int sock, void *data, size_t len, int flags, 
                            struct sockaddr *addr, socklen_t addrlen)
{
	ssize_t ret;

	if (native)
		ret = sendto(sock, data, len, flags, 
			     addr, addrlen);
	else 
		ret = sendto_sf(sock, data, len, flags, 
				addr, addrlen);
	
	if (ret == -1) {
		LOG_ERR("sendto failed: %s\n",
			strerror_sf(errno));
	}

	return ret;
}

static ssize_t scafd_recvfrom(int sock, void *buf, size_t len, int flags, 
                              struct sockaddr *addr, socklen_t *addrlen)
{
	ssize_t ret;

	if (native)
		ret = recvfrom(sock, buf, len, flags, 
                               addr, addrlen);
	else 
		ret = recvfrom_sf(sock, buf, len, flags, 
                                  addr, addrlen);
	
	if (ret == -1) {
		LOG_ERR("recvfrom failed: %s\n",
			strerror_sf(errno));
	}

	return ret;
}

int scafd_send_join(const char *ifname)
{
	LOG_DBG("Join for interface %s\n", ifname);

	return scafd_sendto(ctrlsock, (void *)ifname, strlen(ifname) + 1, 0, 
			    (struct sockaddr *)&ctrlid, sizeof(ctrlid));
}

static void scafd_register_service(struct service_id *srvid)
{
	int ret;
	unsigned long data = 232366;
        
	LOG_DBG("serviceId=%s\n", service_id_to_str(srvid));

	ret = scafd_sendto(ctrlsock, &data, sizeof(data), 0, 
			   (struct sockaddr *)&ctrlid, sizeof(ctrlid));
}

struct libstack_callbacks callbacks = {
	.srvregister = scafd_register_service,
};

int ctrlsock_read(int sock)
{
        unsigned char buf[2000];
        struct sockaddr_sf addr;
        socklen_t addrlen = 0;
        int ret;

        ret = scafd_recvfrom(sock, buf, 2000, 0, 
                             (struct sockaddr *)&addr, &addrlen);

        if (ret > 0) {
                printf("received message from service id %s\n",
                       service_id_to_str(&addr.sf_srvid));
        }

        return ret;
}

int close_ctrlsock(int sock)
{
	if (native)
		return close(ctrlsock);
	
	return close_sf(ctrlsock);
}

int main(int argc, char **argv)
{
	struct sigaction sigact;
#if defined(OS_LINUX)
        struct netlink_handle nlh;
#endif
        fd_set readfds;
	int ret = EXIT_SUCCESS;

	memset(&sigact, 0, sizeof(struct sigaction));

	sigact.sa_handler = &signal_handler;
	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGHUP, &sigact, NULL);
	sigaction(SIGPIPE, &sigact, NULL);

	/* Set controller service id */
	memset(&ctrlid, 0, sizeof(ctrlid));
	ctrlid.sf_family = AF_SCAFFOLD;
	ctrlid.sf_srvid.s_sid16 = htons(666);

	/* Try first a native socket */
	ctrlsock = socket(AF_SCAFFOLD, SOCK_DGRAM, 0);

	if (ctrlsock == -1) {
		if (errno == EAFNOSUPPORT) {
			/* Try libscaffold */
			ctrlsock = socket_sf(AF_SCAFFOLD, SOCK_DGRAM, 0);
			
			if (ctrlsock == -1) {
				LOG_ERR("cannot open controller socket: %s\n",
					strerror_sf(errno));
				return -1;
			}
		} else {
			LOG_ERR("cannot open controller socket: %s\n",
				strerror(errno));
			return -1;
		}
	} else {
		native = 1;
	}
	
	ret = pipe(p);

        if (ret == -1) {
		LOG_ERR("Could not open pipe\n");
		goto fail_pipe;
        }

	ret = libstack_init();

	if (ret == -1) {
		LOG_ERR("Could not init libstack\n");
		goto fail_libstack;
	}
	
	libstack_register_callbacks(&callbacks);

#if defined(OS_LINUX)
	ret = nl_init_handle(&nlh);

	if (ret < 0) {
		LOG_ERR("Could not open netlink socket\n");
                goto fail_netlink;
	}

	ret = netlink_getlink(&nlh);

        if (ret < 0) {
                LOG_ERR("Could not netlink request: %s\n",
                        strerror(errno));
                goto fail_netlink;
        }
#endif
#define MAX(x,y) (x > y ? x : y)

        while (!should_exit) {
                int nfds = 0;

                FD_ZERO(&readfds);
#if defined(OS_LINUX)
                FD_SET(nlh.fd, &readfds);
		nfds = MAX(nlh.fd, nfds);
#endif
                FD_SET(p[0], &readfds);               
                nfds = MAX(p[0], nfds);
                /*
                FD_SET(ctrlsock, &readfds);               
                nfds = MAX(ctrlsock, nfds);
                */
                ret = select(nfds + 1, &readfds, NULL, NULL, NULL);

                if (ret == 0) {
                        LOG_DBG("Timeout...\n");
                } else if (ret == -1) {
			if (errno == EINTR) {
				should_exit = 1;
			} else {
				LOG_ERR("select error: %s\n", 
					strerror(errno));
			}
                } else {
#if defined(OS_LINUX)
                        if (FD_ISSET(nlh.fd, &readfds)) {
                                LOG_DBG("netlink readable\n");
                                read_netlink(&nlh);
                        }
#endif
                        if (FD_ISSET(p[0], &readfds)) {
                                LOG_DBG("pipe readable\n");
                                should_exit = 1;
                        }
                        if (FD_ISSET(ctrlsock, &readfds)) {
                                LOG_DBG("ctrl sock readable\n");
                                ctrlsock_read(ctrlsock);
                        }
                }        
        }
	LOG_DBG("scafd exits\n");

	libstack_unregister_callbacks(&callbacks);
	libstack_fini();
#if defined(OS_LINUX)
        nl_close_handle(&nlh);
#endif
        close(p[0]);
        close(p[1]);
	LOG_DBG("closing control sock\n");
	close_ctrlsock(ctrlsock);
	LOG_DBG("done\n");

out:
        return ret;
#if defined(OS_LINUX)
	nl_close_handle(&nlh);
fail_netlink:
#endif
	libstack_unregister_callbacks(&callbacks);
fail_libstack:
	close(p[0]);
	close(p[1]);
fail_pipe:
	close_ctrlsock(ctrlsock);
	ret = EXIT_FAILURE;
	goto out;
}
