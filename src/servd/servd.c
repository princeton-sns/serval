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
#include <libserval/serval.h>
#include <libservalctrl/hostctrl.h>
#include <libservalctrl/init.h>
#include <netinet/serval.h>
#include <serval/platform.h>
#include <common/timer.h>
#include <common/debug.h>
#if defined(OS_LINUX)
#include "rtnl.h"
#endif
#if defined(OS_BSD)
#include "ifa.h"
#endif

static int router = 0; /* Whether this service daemon is a stub
                          end-host or a router */

static int should_exit = 0;
static int p[2] = { -1, -1 };
static struct timer_queue tq;
static struct {
        struct hostctrl *lhc, *rhc;
} ctx;

static void signal_handler(int sig)
{
        ssize_t ret;
        char q = 'q';
	should_exit = 1;

        ret = write(p[1], &q, 1);

        if (ret < 0) {
                LOG_ERR("Could not signal quit!\n");
        }
}

int servd_interface_changed(const char *ifname)
{
	LOG_DBG("Interface %s changed address. Migrating flows\n", ifname);
        
        return hostctrl_interface_migrate(ctx.lhc, ifname, ifname);
}

static int register_service_remotely(void *context,
                                     const struct service_id *srvid,
                                     unsigned short flags,
                                     unsigned short prefix,
                                     const struct in_addr *local_ip)
{
        struct {
                struct hostctrl *lhc, *rhc;
        } *ctx = context;
	int ret;

	LOG_DBG("serviceID=%s\n", service_id_to_str(srvid));

        ret = hostctrl_service_register(ctx->rhc, srvid, prefix);
    
        return ret;
}

static int unregister_service_remotely(void *context,
                                       const struct service_id *srvid,
                                       unsigned short flags,
                                       unsigned short prefix,
                                       const struct in_addr *local_ip)
{
        struct {
                struct hostctrl *lhc, *rhc;
        } *ctx = context;
        int ret;

	LOG_DBG("serviceID=%s\n", service_id_to_str(srvid));

        ret = hostctrl_service_unregister(ctx->rhc, srvid, prefix);
    
        return ret;
}

static int handle_incoming_registration(void *context,
                                        const struct service_id *srvid,
                                        unsigned short flags,
                                        unsigned short prefix,
                                        const struct in_addr *remote_ip)
{
        struct {
                struct hostctrl *lhc, *rhc;
        } *ctx = context;
#if defined(ENABLE_DEBUG)
        {
                char buf[18];
                LOG_DBG("Remote service %s @ %s registered\n", 
                        service_id_to_str(srvid), 
                        inet_ntop(AF_INET, remote_ip, buf, 18));
        }
#endif
        /* Addd this service the local service table. */
        return hostctrl_service_add(ctx->lhc, srvid, prefix, 
                                    remote_ip);
}

static int handle_incoming_unregistration(void *context,
                                          const struct service_id *srvid,
                                          unsigned short flags,
                                          unsigned short prefix,
                                          const struct in_addr *remote_ip)
{
        struct {
                struct hostctrl *lhc, *rhc;
        } *ctx = context;
#if defined(ENABLE_DEBUG)
        {
                char buf[18];
                LOG_DBG("Remote service %s @ %s unregistered\n", 
                        service_id_to_str(srvid), 
                        inet_ntop(AF_INET, remote_ip, buf, 18));
        }
#endif
        /* Register this service the local service table. */
        return hostctrl_service_remove(ctx->lhc, srvid, prefix, 
                                       remote_ip);
}
                                     
static struct hostctrl_callback lcb = {
        .service_registration = register_service_remotely,
        .service_unregistration = unregister_service_remotely,
};

static struct hostctrl_callback rcb = {
        .service_registration = handle_incoming_registration,
        .service_unregistration = handle_incoming_unregistration,
};

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

        if (!f) {
                LOG_ERR("stdin redirection failed\n");
        }

	f = freopen("/dev/null", "w", stdout);

        if (!f) {
                LOG_ERR("stdout redirection failed\n");
        }

	f = freopen("/dev/null", "w", stderr);

        if (!f) {
                LOG_ERR("stderr redirection failed\n");
        }

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
        unsigned int router_id = 88888, client_id = 55555;
        struct sockaddr_sv raddr, caddr;
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
                } else if (strcmp(argv[0], "-r") == 0 ||
                           strcmp(argv[0], "--router") == 0) {
                        router = 1;
                } else if (strcmp(argv[0], "-rid") == 0 ||
                           strcmp(argv[0], "--router-id") == 0) {
                        char *ptr;
                        router_id = strtoul(argv[1], &ptr, 10);
                        
                        if (!(*ptr == '\0' && argv[1] != '\0')) {
                                fprintf(stderr, "bad router id format '%s',"
                                        " should beinteger string\n",
                                        argv[1]);
                                return -1;
                        }
                } else if (strcmp(argv[0], "-cid") == 0 ||
                           strcmp(argv[0], "--client-id") == 0) {
                        char *ptr;
                        client_id = strtoul(argv[1], &ptr, 10);
                        
                        if (!(*ptr == '\0' && argv[1] != '\0')) {
                                fprintf(stderr, "bad client id format '%s',"
                                        " should be short integer string\n",
                                        argv[1]);
                                return -1;
                        }
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

        ret = timer_queue_init(&tq);

        if (ret == -1) {
                LOG_ERR("timer_queue_init failure\n");
                return -1;
        }

	ret = pipe(p);

        if (ret == -1) {
		LOG_ERR("Could not open pipe\n");
		goto fail_pipe;
        }

	ret = libservalctrl_init();

	if (ret == -1) {
		LOG_ERR("Could not init libservalctrl\n");
		goto fail_libservalctrl;
	}

        ctx.lhc = hostctrl_local_create(&lcb, &ctx, 0);
        
        if (!ctx.lhc) {
                LOG_ERR("Could not create local host control\n");
                goto fail_hostctrl_local;
        }


        memset(&raddr, 0, sizeof(raddr));
        memset(&caddr, 0, sizeof(caddr));
        
        raddr.sv_family = AF_SERVAL;
        raddr.sv_srvid.srv_un.un_id32[0] = htonl(router_id);

        caddr.sv_family = AF_SERVAL;
        caddr.sv_srvid.srv_un.un_id32[0] = htonl(client_id);
	
                
        if (router) {
                ctx.rhc = hostctrl_remote_create_specific(&rcb, &ctx,
                                                          (struct sockaddr *)&raddr, 
                                                          sizeof(raddr),
                                                          (struct sockaddr *)&caddr, 
                                                          sizeof(caddr), HCF_ROUTER);                
        } else {
                ctx.rhc = hostctrl_remote_create_specific(&rcb, &ctx,
                                                          (struct sockaddr *)&caddr, 
                                                          sizeof(caddr),
                                                          (struct sockaddr *)&raddr, 
                                                          sizeof(raddr), 0);
        }
        
        if (!ctx.rhc) {
                LOG_ERR("Could not create remote host control\n");
                goto fail_hostctrl_remote;
        }

        hostctrl_start(ctx.rhc);	
        hostctrl_start(ctx.lhc);

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

                FD_SET(timer_queue_get_signal(&tq), &readfds);
                maxfd = MAX(timer_queue_get_signal(&tq), maxfd);

#if defined(OS_LINUX)
                FD_SET(nlh.fd, &readfds);
		maxfd = MAX(nlh.fd, maxfd);
#endif
                FD_SET(p[0], &readfds);               
                maxfd = MAX(p[0], maxfd);

                if (timer_next_timeout_timeval(&tq, &timeout))
                        t = &timeout;

                ret = select(maxfd + 1, &readfds, NULL, NULL, t);

                if (ret == 0) {
                        ret = timer_handle_timeout(&tq);
                } else if (ret == -1) {
			if (errno == EINTR) {
				should_exit = 1;
			} else {
				LOG_ERR("select: %s\n", 
					strerror(errno));
                                should_exit = 1;
			}
                } else {
                        if (FD_ISSET(timer_queue_get_signal(&tq), &readfds)) {
                                /* Just reschedule timeout */
                        }
#if defined(OS_LINUX)
                        if (FD_ISSET(nlh.fd, &readfds)) {
                                LOG_DBG("netlink readable\n");
                                rtnl_read(&nlh);
                        }
#endif
                        if (FD_ISSET(p[0], &readfds)) {
                                should_exit = 1;
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
        hostctrl_free(ctx.rhc);
fail_hostctrl_remote:
        hostctrl_free(ctx.lhc);
fail_hostctrl_local:
        libservalctrl_fini();
fail_libservalctrl:
	close(p[0]);
	close(p[1]);
fail_pipe:
        timer_queue_fini(&tq);
        
	LOG_DBG("done\n");

        return ret;
}
