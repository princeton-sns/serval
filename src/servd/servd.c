/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- 
 *
 * A service daemon for end-hosts that forwards stack events to a
 * "service router". The deamon can also run on a service router,
 * taking registrations and unregistrations.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
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
#include <netdb.h>
#include <libserval/serval.h>
#include <libservalctrl/hostctrl.h>
#include <libservalctrl/init.h>
#include <netinet/serval.h>
#include <serval/platform.h>
#include <common/timer.h>
#include <common/signal.h>
#include <common/debug.h>
#include <common/list.h>
#include <pthread.h>
#include <poll.h>

#if defined(OS_LINUX)
#include "rtnl.h"
#endif
#if defined(OS_BSD)
#include "ifa.h"
#endif

static int should_exit = 0;
static struct signal exit_signal;
static struct service_id default_service;

struct servd_context {
        struct timer_queue tq;
        int router; /* Whether this service daemon is a stub
                       end-host or a router */
        struct in_addr router_ip;
        int router_ip_set;
        struct sockaddr_sv raddr, caddr;
        struct hostctrl *lhc, *rhc;
        struct list_head reglist;
        struct signal reregister_signal;
        unsigned int num_regs;
        pthread_mutex_t lock; /* Protects the registration list */
};

enum service_type {
        SERVICE_LOCAL,
        SERVICE_REMOTE,
};

struct registration {
        struct list_head lh;
        struct servd_context *ctx;
        enum service_type type;
        struct service_id srvid;
        unsigned short prefix;
        struct in_addr ipaddr;
        struct timer timer;
        int ip_set;
};

#define LOCAL_SERVICE_TIMEOUT (20)
#define REMOTE_SERVICE_TIMEOUT ((LOCAL_SERVICE_TIMEOUT * 2) + 10)

static void registration_timeout_local(struct timer *t)
{
        struct registration *r = (struct registration *)t->data;
        char ip1[18];
        int ret;

        printf("Refreshing registration of service %s:%u %s\n",
               service_id_to_str(&r->srvid), r->prefix,
               inet_ntop(AF_INET, &r->ipaddr, ip1, 18));
        
        ret = hostctrl_service_register(r->ctx->rhc, 
                                        &r->srvid,
                                        r->prefix, 
                                        &r->ipaddr);
        
        if (ret <= 0) {
                fprintf(stderr, "Could not reregister service %s\n",
                        service_id_to_str(&r->srvid));
        }

        timer_schedule_secs(&r->ctx->tq, &r->timer, LOCAL_SERVICE_TIMEOUT);
}

static void registration_timeout_remote(struct timer *t)
{
        struct registration *r = (struct registration *)t->data;
        char ip1[18];

        printf("Registration timeout - service %s:%u %s\n",
               service_id_to_str(&r->srvid), r->prefix,
               inet_ntop(AF_INET, &r->ipaddr, ip1, 18));
        hostctrl_service_remove(r->ctx->lhc, &r->srvid, 
                                r->prefix, &r->ipaddr);
}

static struct registration *registration_add(struct servd_context *ctx,
                                             enum service_type type,
                                             const struct service_id *srvid, 
                                             unsigned short prefix,
                                             const struct in_addr *ipaddr)
{
        struct registration *r;

        r = malloc(sizeof(struct registration));

        if (!r)
                return NULL;

        memset(r, 0, sizeof(struct registration));
        INIT_LIST_HEAD(&r->lh);
        memcpy(&r->srvid, srvid, sizeof(struct service_id));

        if (ipaddr) {
                memcpy(&r->ipaddr, ipaddr, sizeof(struct in_addr));
                r->ip_set = 1;
        }
        timer_init(&r->timer);
        r->timer.data = r;
        r->type = type;
        r->prefix = prefix;
        r->ctx = ctx;
        pthread_mutex_lock(&ctx->lock);
        list_add_tail(&r->lh, &ctx->reglist);
        ctx->num_regs++;
        pthread_mutex_unlock(&ctx->lock);

        if (type == SERVICE_LOCAL) {
                r->timer.callback = registration_timeout_local;
                timer_schedule_secs(&ctx->tq, &r->timer, LOCAL_SERVICE_TIMEOUT);
        } else {
                r->timer.callback = registration_timeout_remote;
                timer_schedule_secs(&ctx->tq, &r->timer, REMOTE_SERVICE_TIMEOUT);
        }

        return r;        
}

static int registration_del(struct servd_context *ctx,
                            const struct service_id *srvid)
{
        struct registration *r;
        int ret = 0;

        pthread_mutex_lock(&ctx->lock);
        
        list_for_each_entry(r, &ctx->reglist, lh) {
                if (memcmp(&r->srvid, srvid, 
                           sizeof(struct service_id)) == 0) {
                        list_del(&r->lh);
                        ret = 1;
                        break;
                }
        }

        pthread_mutex_unlock(&ctx->lock);
        
        if (ret == 1) {
                timer_del(&ctx->tq, &r->timer);
                free(r);
        }

        return ret;
}

static int registration_update_local(struct servd_context *ctx, 
                                     const struct service_id *srvid,
                                     unsigned short prefix,
                                     const struct in_addr *new_ip,
                                     struct in_addr *old_ip)
{
        struct registration *r;
        int ret = 0;

        pthread_mutex_lock(&ctx->lock);
        
        list_for_each_entry(r, &ctx->reglist, lh) {
                if (r->type == SERVICE_LOCAL && 
                    memcmp(&r->srvid, srvid, 
                           sizeof(struct service_id)) == 0 &&
                        r->prefix == prefix) {
                        if (old_ip)
                                memcpy(old_ip, &r->ipaddr, 
                                       sizeof(*old_ip));
                        if (new_ip)
                                memcpy(&r->ipaddr, new_ip, sizeof(*new_ip));
                        ret = 1;
                        break;
                }
        }
        
        pthread_mutex_unlock(&ctx->lock);

        return ret;
        
}

static int registration_update_remote(struct servd_context *ctx, 
                                      const struct service_id *srvid,
                                      unsigned short prefix,
                                      const struct in_addr *new_ip,
                                      const struct in_addr *old_ip)
{
        struct registration *r;
        int ret = 0;

        pthread_mutex_lock(&ctx->lock);
        
        list_for_each_entry(r, &ctx->reglist, lh) {
                if (r->type == SERVICE_REMOTE && 
                    memcmp(&r->srvid, srvid, 
                           sizeof(struct service_id)) == 0 && 
                    memcmp(&r->ipaddr, old_ip, 
                           sizeof(*old_ip)) == 0 && 
                    r->prefix == prefix) {
                        /* The old IP matched the IP stored,
                           so this is the old record. */
                        memcpy(&r->ipaddr, new_ip, 
                               sizeof(*new_ip));
                        ret = 1;
                        timer_mod(&ctx->tq, &r->timer, 
                                  timer_secs(REMOTE_SERVICE_TIMEOUT));
                }
        }
        
        pthread_mutex_unlock(&ctx->lock);

        return ret;
}

static int registration_redo(struct servd_context *ctx,
                             const char *ifname,
                             const struct in_addr *new_ip,
                             const struct in_addr *old_ip)
{
        struct registration *r;
        int ret = 0;

        pthread_mutex_lock(&ctx->lock);
        
        list_for_each_entry(r, &ctx->reglist, lh) {
                char ip1[18], ip2[18];

                printf("Reregistering service %s new_ip=%s old_ip=%s\n",
                       service_id_to_str(&r->srvid),
                       inet_ntop(AF_INET, new_ip, ip1, 18),
                       old_ip ? inet_ntop(AF_INET, old_ip, ip2, 18) : "none");
                
                ret = hostctrl_service_register(ctx->rhc, &r->srvid, 0, 
                                                old_ip);
                
                if (ret <= 0) {
                        fprintf(stderr, "Could not reregister service %s\n",
                                service_id_to_str(&r->srvid));
                }
                
                
                memcpy(&r->ipaddr, new_ip, sizeof(*new_ip));
        }

        pthread_mutex_unlock(&ctx->lock);

        return ret;
}

static int registration_exists(struct servd_context *ctx, 
                               enum service_type type,
                               const struct service_id *srvid,
                               const struct in_addr *ip)
{
        struct registration *r;
        int ret = 0;

        pthread_mutex_lock(&ctx->lock);
        
        list_for_each_entry(r, &ctx->reglist, lh) {
                if (memcmp(&r->srvid, srvid, 
                           sizeof(struct service_id)) == 0 &&
                    r->type == type) {
                        ret = 1;
                        break;
                }
        }

        pthread_mutex_unlock(&ctx->lock);

        return ret;
}

static void registration_clear(struct servd_context *ctx)
{
        while (!list_empty(&ctx->reglist)) {
                struct registration *reg = 
                        list_first_entry(&ctx->reglist, 
                                        struct registration, lh);
                list_del(&reg->lh);
                free(reg);
        }
}

static int name_to_inet_addr(const char *name, struct in_addr *ip)
{
        struct addrinfo *ai;
        struct addrinfo hints = { .ai_family = AF_INET,
                                  .ai_socktype = 0,
                                  .ai_protocol = 0, };
        int ret;

        ret = getaddrinfo(name, "0", &hints, &ai);
        
        if (ret != 0) {
                fprintf(stderr, "getaddrinfo error=%d\n", ret);
                return -1;
        }

        while (ai) {
                if (ai->ai_family == AF_INET) {
                        struct sockaddr_in *in = 
                                (struct sockaddr_in *)ai->ai_addr;
                        memcpy(ip, &in->sin_addr, sizeof(*ip));
                        ret = 1;
                        break;
                }
                ai = ai->ai_next;
        } 
        
        freeaddrinfo(ai);

        return ret;
}

static void signal_handler(int sig)
{
        signal_raise(&exit_signal);
}

/*
static int get_interface_ip(const char *ifname, struct in_addr *ip)
{
	struct ifreq ifr;
	struct sockaddr_in *sin = (struct sockaddr_in *) &ifr.ifr_addr;
	int sock, ret = 0;

	sock = socket(PF_INET, SOCK_STREAM, 0);

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);

	ret = ioctl(sock, SIOCGIFADDR, &ifr);

        if (ret == 0) {
                memcpy(&ip, &sin->sin_addr, 
                       sizeof(struct in_addr));
                ret = 1;
	}

	close(sock);

	return ret;
}
*/

int servd_interface_up(const char *ifname, 
                       const struct in_addr *new_ip,
                       const struct in_addr *old_ip,
                       void *context)
{
        struct servd_context *ctx = context;
        static int first_up_event = 0;

        /* Ignore first interface up event since it is generated as a
           result of detecting the interfaces when the app first
           starts. */
        if (first_up_event == 0) {
                first_up_event = 1;
                return 0;
        }
                
        /* HACK: Delay operations for a short time. The reason is that the
           stack doesn't seem to be immediately ready to use the newly
           assigned address. */
        sleep(1);

        LOG_DBG("lhc=%p rhc=%p\n", ctx->lhc, ctx->rhc);

        /* Make sure our service router entry is present. It might
           have been purged when the interface went down
           previously. Get any new information default route (default
           broadcast) and update it in the callback. */
        if (ctx->router_ip_set && !ctx->router) {

                /* Synchronize with callback before redoing
                   registrations. We need the default service route to
                   send them out. */
                printf("Requesting default service route info\n");
                hostctrl_service_get(ctx->lhc, &default_service, 
                                     0, NULL);

                signal_wait(&ctx->reregister_signal, 5000);
        }

        LOG_DBG("Resending registrations\n");
        
        return registration_redo(ctx, ifname, new_ip, old_ip);
}

static int register_service_remotely(struct hostctrl *hc,
                                     const struct service_id *srvid,
                                     unsigned short flags,
                                     unsigned short prefix,
                                     const struct in_addr *local_ip,
                                     const struct in_addr *prev_ip)
{
        struct servd_context *ctx = hc->context;
        struct in_addr old_ip;
        int ret = 0;

        if (registration_update_local(ctx, srvid, prefix,
                                      local_ip, &old_ip)) {
                ret = hostctrl_service_register(ctx->rhc, srvid, 
                                                prefix, &old_ip);
        } else {
                ret = hostctrl_service_register(ctx->rhc, srvid, 
                                                prefix, NULL);
                if (ret == -1) {
                        fprintf(stderr, "remote registration failed\n");
                } else {
                        struct {
                                struct sockaddr_sv sv;
                                struct sockaddr_in in;
                        } addr;
                        socklen_t addrlen = sizeof(addr);

                        ret = hostctrl_get_local_addr(ctx->rhc, 
                                                      (struct sockaddr *)&addr, &addrlen);

                        if (ret == -1) {
                                fprintf(stderr, "could not get local channel address\n");
                        }
                        registration_add(ctx, SERVICE_LOCAL, srvid, prefix, &addr.in.sin_addr);


                        printf("Local service %s @ %s registered\n", 
                               service_id_to_str(srvid),
                               inet_ntoa(addr.in.sin_addr));
                }
        }

        return ret;
}

static int unregister_service_remotely(struct hostctrl *hc,
                                       const struct service_id *srvid,
                                       unsigned short flags,
                                       unsigned short prefix,
                                       const struct in_addr *local_ip)
{
        struct servd_context *ctx = hc->context;
        int ret = 0;

	printf("Local service=%s unregistered\n", 
               service_id_to_str(srvid));

        if (ctx->rhc) {
                ret = hostctrl_service_unregister(ctx->rhc, srvid, prefix);
    
                registration_del(ctx, srvid);
        }

        return ret;
}

static int handle_incoming_registration(struct hostctrl *hc,
                                        const struct service_id *srvid,
                                        unsigned short flags,
                                        unsigned short prefix,
                                        const struct in_addr *remote_ip, 
                                        const struct in_addr *old_ip)
{
        struct servd_context *ctx = hc->context;
        int ret = 0;

        if (!remote_ip) {
                LOG_ERR("No remote IP!\n");
                return -1;
        }

        if (old_ip && registration_update_remote(ctx, srvid, prefix, 
                                                 remote_ip, old_ip)) {
                /*
                char ip1[18], ip2[18];    
                printf("Remote service %s:%u @ %s <- %s reregistered\n", 
                       service_id_to_str(srvid), prefix,
                       inet_ntop(AF_INET, remote_ip, ip1, sizeof(ip1)),
                       old_ip ? inet_ntop(AF_INET, old_ip, ip2, sizeof(ip2)) : "none");
                */
                ret = hostctrl_service_modify(ctx->lhc, srvid, prefix, 
                                              0, 0, old_ip, remote_ip);
        } else {
                /* Add this service the local service table. */
                char buf[18];
                
                printf("Remote service %s:%u @ %s registered\n", 
                       service_id_to_str(srvid), prefix,
                       inet_ntop(AF_INET, remote_ip, buf, sizeof(buf)));
                
                registration_add(ctx, SERVICE_REMOTE, srvid, 
                                 prefix, remote_ip);

                ret = hostctrl_service_add(ctx->lhc, srvid, prefix, 
                                           0, 0, remote_ip);
        }

        return ret;
}

static int handle_incoming_unregistration(struct hostctrl *hc,
                                          const struct service_id *srvid,
                                          unsigned short flags,
                                          unsigned short prefix,
                                          const struct in_addr *remote_ip)
{
        struct servd_context *ctx = hc->context;
        int ret = 0;
        
        if (registration_exists(ctx, SERVICE_REMOTE, srvid, remote_ip)) {
                char buf[18];
                
                printf("Remote service %s @ %s unregistered\n", 
                       service_id_to_str(srvid), 
                       inet_ntop(AF_INET, remote_ip, buf, 18));
                
                /* Remove this service from the local service
                   table. */
                ret = hostctrl_service_remove(ctx->lhc, srvid, prefix, 
                                              remote_ip);
        }

        return ret;
}

/*
  Callback that returns the result of a previous service 'get'.

  We use it to set the default service resolve rule to a fixed service
  router IP.
 */
static int local_service_get_result(struct hostctrl *hc,
                                    unsigned int xid,
                                    int retval,
                                    const struct service_info *si,
                                    unsigned int num)
{
        struct servd_context *ctx = hc->context;
        int ret = 0;
        unsigned int i = 0;

        for (i = 0; i < num; i++) {
#if defined(ENABLE_DEBUG)
                char buf[18], buf2[18];
                LOG_DBG("GET: %s valid=%s is_router=%s router_ip_set=%s"
                        " prio=%u weight=%u"
                        " requested_ip=%s new_ip=%s\n",
                        service_id_to_str(&si->srvid),
                        si->srvid_flags & SVSF_INVALID ? "false" : "true",
                        ctx->router ? "true" : "false",
                        ctx->router_ip_set ? "true" : "false",
                        si->priority, si->weight,
                        inet_ntop(AF_INET, &si->address, buf, 18),
                        inet_ntop(AF_INET, &ctx->router_ip, buf2, 18));
#endif
                sleep(1);
                
                if (si->srvid_flags & SVSF_INVALID) {
                        LOG_DBG("No default service route set\n");
                        /* There was no existing route, the 'get' returned
                           nothing. Just add our default route */
                        ret = hostctrl_service_add(ctx->lhc, &default_service,
                                                   0, 1, 0, &ctx->router_ip);
                } else if (!ctx->router && ctx->router_ip_set && 
                           memcmp(&default_service, &si->srvid, 
                                  sizeof(default_service)) == 0 && 
                           memcmp(&ctx->router_ip, &si->address, sizeof(si->address)) != 0) {
#if defined(ENABLE_DEBUG)
                        char buf[18], buf2[18];
                        LOG_DBG("Replacing default route old=%s new=%s\n",
                                inet_ntop(AF_INET, &si->address, buf, 18),
                                inet_ntop(AF_INET, &ctx->router_ip, buf2, 18));
#endif
                        /* The 'get' for the default service returned
                           something. Update the existing entry */
                        ret = hostctrl_service_modify(ctx->lhc, &si->srvid, 
                                                      si->srvid_prefix_bits, si->priority,
                                                      si->weight, &si->address, &ctx->router_ip);
                }
                
        }
        
        /* Check if we need to perform the deferred reregistration of
           services now that we have a new default service router
                   (which was probably a result of an interface up/down). */
        if (ctx->router_ip_set && !ctx->router && 
            signal_num_waiting(&ctx->reregister_signal)) {
                signal_raise(&ctx->reregister_signal);
        }
        
        return ret;
}
                                   
static struct hostctrl_callback lcb = {
        .service_registration = register_service_remotely,
        .service_unregistration = unregister_service_remotely,
        .service_get_result = local_service_get_result,
        .start = NULL,
        .stop = NULL,
};

static struct hostctrl_callback rcb = {
        .service_registration = handle_incoming_registration,
        .service_unregistration = handle_incoming_unregistration,
        .start = NULL,
        .stop = NULL,
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

static void print_usage(void)
{
        printf("Usage: servd [ OPTIONS ]\n"
               "where OPTIONS:\n"
               "\t-d,--daemon\t\t\t - Run in the background as a daemon.\n"
               "\t-r,--router\t\t\t - Run in router mode, accepting registrations.\n"
               "\t-rid,--router-id SERVICEID\t - Specify the SERVICEID of a router.\n"
               "\t-cid,--client-id SERVICEID\t - Specify the SERVICEID of a client.\n"
               "\t-rip,--router-ip ROUTER_IP\t - Specify the IP of a service router.\n"
               "\t-h,--help\t\t\t - Print this help message.\n");
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
        struct servd_context ctx;

        memset(&default_service, 0, sizeof(default_service));
	memset(&sigact, 0, sizeof(struct sigaction));
        memset(&ctx, 0, sizeof(ctx));
        INIT_LIST_HEAD(&ctx.reglist);
        pthread_mutex_init(&ctx.lock, NULL);

	sigact.sa_handler = &signal_handler;
	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);
	sigaction(SIGHUP, &sigact, NULL);
	sigaction(SIGPIPE, &sigact, NULL);

        argc--;
	argv++;
        
	while (argc) {
                if (strcmp(argv[0], "-h") == 0 ||
                    strcmp(argv[0], "--help") == 0) {
                        print_usage();
                        return 0;
                } else if (strcmp(argv[0], "-d") == 0 ||
                    strcmp(argv[0], "--daemon") == 0) {
                        daemon = 1;
                } else if (strcmp(argv[0], "-r") == 0 ||
                           strcmp(argv[0], "--router") == 0) {
                        LOG_DBG("Host is service router\n");
                        ctx.router = 1;
                } else if (strcmp(argv[0], "-rid") == 0 ||
                           strcmp(argv[0], "--router-id") == 0) {
                        char *ptr;

                        if (argc < 1) {
                                fprintf(stderr, "No router ID given\n");
                                return -1;
                        }

                        router_id = strtoul(argv[1], &ptr, 10);
                        
                        if (!(*ptr == '\0' && argv[1] != '\0')) {
                                fprintf(stderr, "bad router id format '%s',"
                                        " should beinteger string\n",
                                        argv[1]);
                                return -1;
                        }

                        argc--;
                        argv++;
                } else if (strcmp(argv[0], "-rip") == 0 ||
                           strcmp(argv[0], "--router-ip") == 0) {
                        if (argc < 1) {
                                fprintf(stderr, "No router IP given\n");
                                return -1;
                        }
                        if (name_to_inet_addr(argv[1], &ctx.router_ip) == 1 ||
                            inet_pton(AF_INET, argv[1], &ctx.router_ip) == 1) {
                                LOG_DBG("Service router IP is %s\n", argv[1]);
                                ctx.router_ip_set = 1;
                        }
                } else if (strcmp(argv[0], "-cid") == 0 ||
                           strcmp(argv[0], "--client-id") == 0) {
                        char *ptr;

                        if (argc < 1) {
                                fprintf(stderr, "No client ID given\n");
                                return -1;
                        }

                        client_id = strtoul(argv[1], &ptr, 10);
                        
                        if (!(*ptr == '\0' && argv[1] != '\0')) {
                                fprintf(stderr, "bad client id format '%s',"
                                        " should be short integer string\n",
                                        argv[1]);
                                return -1;
                        }

                        argc--;
                        argv++;
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

        ret = timer_queue_init(&ctx.tq);

        if (ret == -1) {
                LOG_ERR("timer_queue_init failure\n");
                return -1;
        }

	ret = signal_init(&exit_signal);

        if (ret == -1) {
		LOG_ERR("Could not init exit signal\n");
		goto fail_exit_signal;
        }

	ret = signal_init(&ctx.reregister_signal);

        if (ret == -1) {
		LOG_ERR("Could not init reregister signal\n");
		goto fail_reregister_signal;
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

        ctx.raddr.sv_family = AF_SERVAL;
        ctx.raddr.sv_srvid.srv_un.un_id32[0] = htonl(router_id);

        ctx.caddr.sv_family = AF_SERVAL;
        ctx.caddr.sv_srvid.srv_un.un_id32[0] = htonl(client_id);
	
        if (ctx.router) {
                ctx.rhc = hostctrl_remote_create_specific(&rcb, &ctx,
                                                          (struct sockaddr *)&ctx.raddr, 
                                                          sizeof(ctx.raddr),
                                                          (struct sockaddr *)&ctx.caddr, 
                                                          sizeof(ctx.caddr), HCF_ROUTER);                
        } else {
                ctx.rhc = hostctrl_remote_create_specific(&rcb, &ctx,
                                                          (struct sockaddr *)&ctx.caddr, 
                                                          sizeof(ctx.caddr),
                                                          (struct sockaddr *)&ctx.raddr, 
                                                          sizeof(ctx.raddr), 0);
        }

        if (!ctx.rhc) {
                LOG_ERR("Could not create remote host control\n");
                goto fail_hostctrl_remote;
        }

        hostctrl_start(ctx.rhc);
        hostctrl_start(ctx.lhc);

        /* If we are a client and have a fixed IP for the service
           router, then replace an existing "default" service rule by
           querying for the current one and modifying it in the
           resulting callback. */
        if (ctx.router_ip_set && !ctx.router) {
                hostctrl_service_get(ctx.lhc, &default_service, 0, NULL);
                if (signal_wait(&ctx.reregister_signal, 3000) == 0) {
                        LOG_DBG("Timeout when retrieving default entry\n");
                }
        }

#if defined(OS_LINUX)
	ret = rtnl_init(&nlh, &ctx);

	if (ret < 0) {
		LOG_ERR("Could not open netlink socket\n");
                goto fail_netlink;
	}

	ret = rtnl_getaddr(&nlh);

        if (ret < 0) {
                LOG_ERR("Could not netlink request: %s\n",
                        strerror(errno));
                rtnl_fini(&nlh);
                goto fail_netlink;
        }
#endif

#if defined(OS_BSD)
        ret = ifaddrs_init(&ctx.tq);

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

                FD_SET(timer_queue_get_signal(&ctx.tq), &readfds);
                maxfd = MAX(timer_queue_get_signal(&ctx.tq), maxfd);

#if defined(OS_LINUX)
                FD_SET(nlh.fd, &readfds);
		maxfd = MAX(nlh.fd, maxfd);
#endif
                FD_SET(signal_get_fd(&exit_signal), &readfds);
                maxfd = MAX(signal_get_fd(&exit_signal), maxfd);

                if (timer_next_timeout_timeval(&ctx.tq, &timeout))
                        t = &timeout;

                ret = select(maxfd + 1, &readfds, NULL, NULL, t);

                if (ret == 0) {
                        ret = timer_handle_timeout(&ctx.tq);
                } else if (ret == -1) {
			if (errno == EINTR) {
                                LOG_DBG("Interruped!\n");
			} else {
				LOG_ERR("select: %s\n", 
					strerror(errno));
                                should_exit = 1;
			}
                } else {
                        if (FD_ISSET(timer_queue_get_signal(&ctx.tq), &readfds)) {
                                /* Just reschedule timeout */
                                timer_queue_signal_lower(&ctx.tq);
                        }
#if defined(OS_LINUX)
                        if (FD_ISSET(nlh.fd, &readfds)) {
                                rtnl_read(&nlh);
                        }
#endif
                        if (FD_ISSET(signal_get_fd(&exit_signal), &readfds)) {
                                should_exit = 1;
                        }
                }        
        }

	LOG_DBG("servd exits\n");

        if (ctx.router_ip_set && !ctx.router) {
                hostctrl_service_remove(ctx.lhc, &ctx.raddr.sv_srvid, 0, 
                                        &ctx.router_ip);
        }

#if defined(OS_BSD)
        ifaddrs_fini(&ctx.tq);
 fail_ifaddrs:
#endif
#if defined(OS_LINUX)
	rtnl_fini(&nlh);
 fail_netlink:
#endif
        hostctrl_free(ctx.rhc);
        ctx.rhc = NULL;
 fail_hostctrl_remote:
        hostctrl_free(ctx.lhc);
 fail_hostctrl_local:
        libservalctrl_fini();
 fail_libservalctrl:
        signal_destroy(&ctx.reregister_signal);
 fail_reregister_signal:
        signal_destroy(&exit_signal);
 fail_exit_signal:
        timer_queue_fini(&ctx.tq);

        registration_clear(&ctx);
        pthread_mutex_destroy(&ctx.lock);
	LOG_DBG("done\n");

        return ret;
}
