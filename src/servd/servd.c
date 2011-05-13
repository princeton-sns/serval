/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h> 
#include <sys/select.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <libstack/stack.h>
#include <libserval/serval.h>
#include <netinet/serval.h>
#include <serval/platform.h>
#include "debug.h"
#if defined(OS_LINUX)
#include "rtnl.h"
#endif
#if defined(OS_BSD)
#include "ifa.h"
#endif
#include "timer.h"

static int ctrlsock = -1; /* socket to communicate with controller */
static int native = 0; /* Whether the socket is native or libserval */

static int should_exit = 0;
static int p[2] = { -1, -1 };
struct sockaddr_sv ctrlid;

static int join_timeout(struct timer *t);

static void signal_handler(int sig)
{
        ssize_t ret;
        char q = 'q';
	should_exit = 1;
        ret = write(p[1], &q, 1);
}

static ssize_t servd_sendto(int sock, void *data, size_t len, int flags, 
                            struct sockaddr *addr, socklen_t addrlen)
{
	ssize_t ret;

	if (native)
		ret = sendto(sock, data, len, flags, 
			     addr, addrlen);
	else 
		ret = sendto_sv(sock, data, len, flags, 
				addr, addrlen);
	
	if (ret == -1) {
		LOG_ERR("sendto failed: %s\n",
			strerror_sv(errno));
	}

	return ret;
}

static ssize_t servd_recvfrom(int sock, void *buf, size_t len, int flags, 
                              struct sockaddr *addr, socklen_t *addrlen)
{
	ssize_t ret;

	if (native)
		ret = recvfrom(sock, buf, len, flags, 
                               addr, addrlen);
	else 
		ret = recvfrom_sv(sock, buf, len, flags, 
                                  addr, addrlen);
	
	if (ret == -1) {
		LOG_ERR("recvfrom failed: %s\n",
			strerror_sv(errno));
	}

	return ret;
}

int join_timeout(struct timer *t)
{
        int ret;
        
        LOG_DBG("Join timeout for %s. Setting host control mode\n",
                (char *)t->data);

        ret = libstack_configure_interface((char *)t->data, 
                                           NULL, IFFLAG_HOST_CTRL_MODE);

        timer_destroy(t);

        return ret;
}

void join_timer_destroy(struct timer *t)
{        
        free(t->data);
        timer_free(t);
}

int servd_send_join(const char *ifname)
{
        struct timer *t;
        
	LOG_DBG("Join for interface %s\n", ifname);

        t = timer_new_callback(join_timeout, NULL);
        
        if (!t)
                return -1;

        t->data = malloc(strlen(ifname) + 1);
        
        if (!t->data) {
                timer_free(t);
                return -1;
        }
        strcpy(t->data, ifname);
        t->destruct = join_timer_destroy;

        timer_schedule_secs(t, 5);

	return servd_sendto(ctrlsock, (void *)ifname, strlen(ifname) + 1, 0, 
                            (struct sockaddr *)&ctrlid, sizeof(ctrlid));
}

static void servd_register_service(struct service_id *srvid)
{
	int ret;
	unsigned long data = 232366;
        
        if (!srvid)
                return;

	LOG_DBG("serviceID=%s\n", service_id_to_str(srvid));

        ret = servd_sendto(ctrlsock, &data, sizeof(data), 0, 
			   (struct sockaddr *)&ctrlid, sizeof(ctrlid));
}

static struct libstack_callbacks callbacks = {
	.srvregister = servd_register_service,
};

int ctrlsock_read(int sock)
{
        unsigned char buf[2000];
        struct sockaddr_sv addr;
        socklen_t addrlen = 0;
        int ret;

        ret = servd_recvfrom(sock, buf, 2000, 0, 
                             (struct sockaddr *)&addr, &addrlen);

        if (ret > 0) {
                printf("received message from serviceID %s\n",
                       service_id_to_str(&addr.sv_srvid));
        }

        return ret;
}

int close_ctrlsock(int sock)
{
	if (native)
		return close(ctrlsock);
	
	return close_sv(ctrlsock);
}

static int daemonize(void)
{
        int i, sid;
	FILE *f;

        /* check if already a daemon */
	if (getppid() == 1) 
                return -1; 
	
	i = fork();

	if (i < 0) {
		fprintf(stderr, "Fork error...\n");
                return -1;
	}
	if (i > 0) {
		//printf("Parent done... pid=%u\n", getpid());
                exit(EXIT_SUCCESS);
	}
	/* new child (daemon) continues here */
	
	/* Change the file mode mask */
	umask(0);
		
	/* Create a new SID for the child process */
	sid = setsid();
	
	if (sid < 0)
		return -1;
	
	/* 
	 Change the current working directory. This prevents the current
	 directory from being locked; hence not being able to remove it. 
	 */
	if (chdir("/") < 0) {
		return -1;
	}
	
	/* Redirect standard files to /dev/null */
	f = freopen("/dev/null", "r", stdin);
	f = freopen("/dev/null", "w", stdout);
	f = freopen("/dev/null", "w", stderr);

        return 0;
}

int main(int argc, char **argv)
{
	struct sigaction sigact;
#if defined(OS_LINUX)
        struct netlink_handle nlh;
#endif
        fd_set readfds;
        int daemon = 0;
	int ret = EXIT_SUCCESS;

	memset(&sigact, 0, sizeof(struct sigaction));

	sigact.sa_handler = &signal_handler;
	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);
	sigaction(SIGHUP, &sigact, NULL);
	sigaction(SIGPIPE, &sigact, NULL);

        argc--;
	argv++;
        
	while (argc) {
                if (strcmp(argv[0], "-d") == 0 ||
                    strcmp(argv[0], "--daemon") == 0) {
                        daemon = 1;
		}
		argc--;
		argv++;
	}	
      
        if (daemon) {
                LOG_DBG("going daemon...\n");
                ret = daemonize();
                
                if (ret < 0) {
                        LOG_ERR("Could not make daemon\n");
                        return ret;
                } 
        }

        ret = timer_list_init();

        if (ret == -1) {
                LOG_ERR("timer_list_init failure\n");
                return -1;
        }

	/* Set controller service id */
	memset(&ctrlid, 0, sizeof(ctrlid));
	ctrlid.sv_family = AF_SERVAL;
	ctrlid.sv_srvid.s_sid16[0] = htons(666);

	/* Try first a native socket */
	ctrlsock = socket(AF_SERVAL, SOCK_DGRAM, 0);

	if (ctrlsock == -1) {
                switch (errno) {
		case EAFNOSUPPORT:
                case EPROTONOSUPPORT:
			/* Try libserval */
			ctrlsock = socket_sv(AF_SERVAL, SOCK_DGRAM, 0);
			
			if (ctrlsock == -1) {
				LOG_ERR("controller socket: %s\n",
					strerror_sv(errno));
				goto fail_ctrlsock;
			}
                        break;
                default:
			LOG_ERR("controller socket (native): %s\n",
				strerror(errno));
                        goto fail_ctrlsock;
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
	ret = rtnl_init(&nlh);

	if (ret < 0) {
		LOG_ERR("Could not open netlink socket\n");
                goto fail_netlink;
	}

	ret = rtnl_getaddr(&nlh);

        if (ret < 0) {
                LOG_ERR("Could not netlink request: %s\n",
                        strerror(errno));
                rtnl_close(&nlh);
                goto fail_netlink;
        }
#endif

#if defined(OS_BSD)
        ret = ifaddrs_init();

        if (ret < 0) {
                LOG_ERR("Could not discover interfaces\n");
                goto fail_ifaddrs;
        }
#endif
#define MAX(x,y) (x > y ? x : y)

        while (!should_exit) {
                int maxfd = 0;
                struct timeval timeout = { 0, 0 }, *t = NULL;

                FD_ZERO(&readfds);

                FD_SET(timer_list_get_signal(), &readfds);
                maxfd = MAX(timer_list_get_signal(), maxfd);

#if defined(OS_LINUX)
                FD_SET(nlh.fd, &readfds);
		maxfd = MAX(nlh.fd, maxfd);
#endif
                FD_SET(p[0], &readfds);               
                maxfd = MAX(p[0], maxfd);
                /*
                FD_SET(ctrlsock, &readfds);               
                nfds = MAX(ctrlsock, nfds);
                */
                if (timer_next_timeout_timeval(&timeout))
                        t = &timeout;

                ret = select(maxfd + 1, &readfds, NULL, NULL, t);

                if (ret == 0) {
                        ret = timer_handle_timeout();
                } else if (ret == -1) {
			if (errno == EINTR) {
				should_exit = 1;
			} else {
				LOG_ERR("select: %s\n", 
					strerror(errno));
                                should_exit = 1;
			}
                } else {
                        if (FD_ISSET(timer_list_get_signal(), &readfds)) {
                                /* Just reschedule timeout */
                        }
#if defined(OS_LINUX)
                        if (FD_ISSET(nlh.fd, &readfds)) {
                                LOG_DBG("netlink readable\n");
                                rtnl_read(&nlh);
                        }
#endif
                        if (FD_ISSET(p[0], &readfds)) {
                                LOG_DBG("pipe readable\n");
                                should_exit = 1;
                        }
                        if (FD_ISSET(ctrlsock, &readfds)) {
                                LOG_DBG("ctrl sock readable\n");
                                ret = ctrlsock_read(ctrlsock);

                                if (ret == 0) {
                                        LOG_DBG("ctrl sock closed by peer\n");
                                        should_exit = 1;
                                }
                        }
                }        
        }

	LOG_DBG("servd exits\n");

#if defined(OS_BSD)
        ifaddrs_fini();
fail_ifaddrs:
#endif
#if defined(OS_LINUX)
	rtnl_close(&nlh);
fail_netlink:
#endif
	libstack_unregister_callbacks(&callbacks);
        libstack_fini();
fail_libstack:
	close(p[0]);
	close(p[1]);
fail_pipe:
	close_ctrlsock(ctrlsock);
fail_ctrlsock:
        timer_list_fini();

	LOG_DBG("done\n");

        return ret;
}
