/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h> 
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <libstack/stack.h>
#include <libserval/serval.h>
#include <netinet/serval.h>
#include <serval/platform.h>
#include <pcl.h>
#include <getopt.h>
#include <assert.h>

#include "resolver.h"
#include "resolution_path.h"
#include "server_resolver.h"
#include "task.h"
#include "message_channel.h"
#include "time_util.h"
#include "service_util.h"
#include "cmwc.h"

#include "debug.h"
#if defined(OS_LINUX)
#include <sys/ioctl.h>
#include <net/if.h>
#endif
#if defined(OS_BSD)
#include <ifaddrs.h>
#endif

#include "timer.h"

static volatile int router_running = FALSE;
static stack_t signal_stack;

extern void udp_channel_destroy();
extern void udp_channel_create();
extern void create_resolution_path(resolution_path* respath);

extern int create_client_service_resolver(struct sockaddr_sv* local,
        struct sv_instance_addr* remote, uint32_t uptime, uint32_t capabilities, uint32_t capacity,
        uint8_t relation, service_resolver* resolver);

extern void create_local_resolver(struct sockaddr_sv* local, uint32_t capabilities,
        uint32_t capacity, service_resolver* default_res, resolution_path* spath,
        service_resolver* resolver);

static int daemonize(void) {
    int i, sid;
    FILE *f;

    /* check if already a daemon */
    if(getppid() == 1)
        return -1;

    i = fork();

    if(i < 0) {
        fprintf(stderr, "Fork error...\n");
        return -1;
    }
    if(i > 0) {
        //printf("Parent done... pid=%u\n", getpid());
        exit(EXIT_SUCCESS);
    }
    /* new child (daemon) continues here */

    /* Change the file mode mask */
    umask(0);

    /* Create a new SID for the child process */
    sid = setsid();

    if(sid < 0)
        return -1;

    /*
     Change the current working directory. This prevents the current
     directory from being locked; hence not being able to remove it.
     */
    if(chdir("/") < 0) {
        return -1;
    }

    /* Redirect standard files to /dev/null */
    f = freopen("/dev/null", "r", stdin);
    f = freopen("/dev/null", "w", stdout);
    f = freopen("/dev/null", "w", stderr);

    return 0;
}

static void terminate_handler(int sig) {
    /*set running to 0 cleanup code*/
    printf("Terminating servie router\n");
    router_running = FALSE;
}

static void interrupt_handler(int sig) {
    /*just continue on*/

}

static void initialize_signals() {
    /*all signal handling should occur on a separate stack*/
    bzero(&signal_stack, sizeof(signal_stack));
    signal_stack.ss_size = SIGSTKSZ;
    signal_stack.ss_flags = 0;

    if((signal_stack.ss_sp = malloc(SIGSTKSZ)) == NULL) {
        perror("Could not allocated signal stack");
        exit(1);
    }

    if(sigaltstack(&signal_stack, NULL)) {
        perror("Could not set the signal stack");
        exit(1);
    }

    struct sigaction sa;

    bzero(&sa, sizeof(struct sigaction));
    sa.sa_handler = terminate_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_ONSTACK;

    /*termination cleanup signal handlers - should be non-interruptible*/
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    /*let sigint continue - no syscall SA_RESTART */

    bzero(&sa, sizeof(struct sigaction));
    sa.sa_handler = interrupt_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_ONSTACK;

    sigaction(SIGINT, &sa, NULL);

    /*ignore sigpipe - for those pesky TCP/connected UDP socket breaks*/
    bzero(&sa, sizeof(struct sigaction));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGPIPE, &sa, NULL);
}

static void initialize_system() {
    init_time(DEFAULT_RESOLUTION_INTERVAL);
    init_rand(get_current_time());
    co_thread_init();
    initialize_tasks(0);
    udp_channel_create();
}

static void terminate_system() {

    finalize_tasks();
    udp_channel_destroy();
    co_thread_cleanup();

}

struct option router_options[4] = {

{ "daemon", 0, NULL, 'd' }, { "mode", 1, NULL, 'm' }, { "config", 1, NULL, 'c' }, {
        NULL,
        0,
        NULL,
        0 }

};

void init_local_address_list(void* resolver) {

#if defined(OS_LINUX)
    struct ifconf iconf;
    iconf.ifc_len = sizeof(struct ifreq) * 20;
    iconf.ifc_buf = (char*) malloc(iconf.ifc_len);

    int sfd = socket(AF_INET, SOCK_DGRAM, 0);

    if(sfd < 0) {
        LOG_ERR("Could not open dgram socket: %s\n", strerror(errno));
        return;
    }

    if(ioctl(sfd, SIOCGIFCONF, &iconf)) {
        //error!
        LOG_ERR("ioctl(SIOCGIFHWADDR) error: %s\n", strerror(errno));
        close(sfd);
        return;
    }
    int i = 0;
    for(; i < iconf.ifc_len / sizeof(struct ifreq); i++) {
        if(iconf.ifc_req[i].ifr_addr.sa_family == AF_INET) {
            if(ntohl(((struct sockaddr_in*) &iconf.ifc_req[i].ifr_addr)->sin_addr.s_addr) >> 24 == 127) {
                continue;
            }

            resolver_add_address(resolver,
                    (struct net_addr*) &((struct sockaddr_in*) &iconf.ifc_req[i].ifr_addr)->sin_addr);
        }
    }

    close(sfd);

#endif

#if defined(OS_BSD)
    struct ifaddrs * addrs;

    if(getifaddrs(&addrs)) {
        LOG_ERR("Could not get interface addresses: %s\n", strerror(errno));
        return;
    }

    while(addrs) {

        if(addrs->ifa_addr->sa_family == AF_INET) {
            resolver_add_address(resolver,
                    (struct net_addr*) &((struct sockaddr_in*) addrs->ifa_addr)->sin_addr);
        } else {

        }

        addrs = addrs->ifa_next;
    }

    freeifaddrs(addrs);
#endif

}

int main(int argc, char **argv) {

    int daemon = FALSE;
    int capabilities = SVPF_STUB;
    char* config = NULL;
    int ret = EXIT_SUCCESS;

    initialize_signals();

    int opt = 0;
    int longind = 0;
    while ((opt = getopt_long(argc, argv, "dm:c:", router_options, &longind)) != -1) {
        //printf("opt: %c\n", opt);
        switch (opt) {
        case 'd':
            daemon = TRUE;
            break;
        case 'm':
            if(strcasecmp(optarg, "stub") == 0) {
                capabilities |= SVPF_STUB;
            } else if(strcasecmp(optarg, "transit") == 0) {
                capabilities |= SVPF_TRANSIT;
            } else {
                fprintf(stderr, "Invalid mode: %s, should be one of <stub, transit>", optarg);
                return -1;
            }
            break;
        case 'c':
            config = optarg;
            break;
        case '?':
            break;
        }
    }
    /*command line options*/
    opt = optind;

    if(daemon) {
        LOG_DBG("going daemon...\n");
        ret = daemonize();

        if(ret < 0) {
            LOG_ERR("Could not make daemon\n");
            return ret;
        }
    }

    initialize_system();

    /* if the config exists, load it - TODO*/

    struct sockaddr_sv resolver_id;
    memcpy(&resolver_id, &service_router_prefix, sizeof(service_router_prefix));
    initialize_service_id(&resolver_id.sv_srvid, resolver_id.sv_prefix_bits);

    LOG_DBG("Generated resolver service ID: %s\n", service_id_to_str(&resolver_id.sv_srvid));

    struct sv_instance_addr def_resolver_id;
    bzero(&def_resolver_id, sizeof(def_resolver_id));
    memcpy(&def_resolver_id.service, &service_router_prefix, sizeof(service_router_prefix));

    /* create the resolution path - must register with the stack first before binding any service IDs*/
    resolution_path rpath;
    create_resolution_path(&rpath);

    service_resolver def_resolver;
    /*no instance address for the default resolver*/
    if(create_client_service_resolver(&resolver_id, &def_resolver_id, 0, SVPF_STUB,
            DEFAULT_CAPACITY, RELATION_UNKNOWN, &def_resolver)) {
        LOG_ERR("Could not create default client resolver!\n");
        terminate_system();
        exit(1);
    }

    service_resolver resolver;
    create_local_resolver(&resolver_id, capabilities, DEFAULT_CAPACITY, &def_resolver, &rpath,
            &resolver);

    /*add the local addresses */
    init_local_address_list(resolver.target);

    int count = resolver_get_address_count(resolver.target);

    int i = 0;
    struct net_addr* address;
    for (i = 0; i < count; i++) {
        address = resolver_get_address(resolver.target, i);
        printf("Local resolver address: %s\n", inet_ntoa(address->net_un.un_ip));
    }

    rpath.interface->set_resolver(rpath.target, &resolver);

    rpath.interface->initialize(rpath.target);
    printf("STARTING RESOLUTION PATH\n");
    rpath.interface->start(rpath.target);

    if(capabilities & SVPF_TRANSIT) {
        rpath.interface->set_transit(rpath.target, TRUE);
    }

    /* create the local server */
    resolver.interface->initialize(resolver.target);

    def_resolver.interface->initialize(def_resolver.target);
    def_resolver.interface->incref(def_resolver.target);

    printf("STARTING RESOLVERS\n");
    def_resolver.interface->start(def_resolver.target);
    resolver.interface->start(resolver.target);

    /*then we init the default client/remote resolver and local resolvers - which call serval bind()*/
    /*TODO bad interface design if the code is hyper-sensitive to ordering at this level
     * local resolver must init first to initialize all its data structures
     */
    /* create the rpc handler */
    struct server_rpc_handler rpc_handler;
    init_server_rpc_handler(&rpc_handler, &resolver);
    /* initialize everything */
    server_rpc_handler_initialize(&rpc_handler);
    server_rpc_handler_start(&rpc_handler);

    struct timespec nap;
    bzero(&nap, sizeof(nap));
    nap.tv_sec = 10;
    int retval;
    router_running = 1;
    while (router_running) {
        retval = nanosleep(&nap, NULL);

        if(retval) {
            /*interrupted*/
            LOG_DBG("Service router main thread interrupted: %s\n", strerror(errno));
        }
    }

    LOG_DBG("Stopping...\n");

    server_rpc_handler_stop(&rpc_handler);
    resolver.interface->stop(resolver.target);
    def_resolver.interface->stop(def_resolver.target);
    rpath.interface->stop(rpath.target);

    LOG_DBG("Finalizing...\n");
    server_rpc_handler_finalize(&rpc_handler);
    resolver.interface->finalize(resolver.target);
    def_resolver.interface->finalize(def_resolver.target);
    rpath.interface->finalize(rpath.target);

    terminate_system();

    LOG_DBG("done\n");

    return ret;
}
