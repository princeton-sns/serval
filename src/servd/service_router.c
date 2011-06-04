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

static struct sockaddr_sv resolver_id;
static resolution_path* rpath = NULL;
static service_resolver* def_resolver = NULL;
static service_resolver* resolver = NULL;
static struct server_rpc_handler* rpc_handler = NULL;

extern void udp_channel_destroy();
extern void udp_channel_create();
extern resolution_path* create_resolution_path();

extern service_resolver* create_client_service_resolver(struct sockaddr_sv* local,
        struct sv_instance_addr* remote, uint32_t uptime, uint32_t capabilities, uint32_t capacity,
        uint8_t relation);

extern service_resolver* create_local_service_resolver(struct sockaddr_sv* local,
        uint32_t capabilities, uint32_t capacity, service_resolver* default_res,
        resolution_path* spath);
extern resolver_rpc* client_get_messaging(service_resolver* resolver);

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
    if(rpc_handler)
        free(rpc_handler);
    if(resolver)
        free(resolver);
    if(def_resolver)
        free(def_resolver);
    if(rpath)
        free(rpath);

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

void init_local_address_list(service_resolver* resolver) {

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

static int parse_service_desc(char* sid_str, struct sockaddr_sv* service) {
    //TODO
    return 0;
}

static int load_config(const char* config_path) 
{
    char line_buffer[1024];
    char* temp;
    service_resolver* peer = NULL;
    GPtrArray* peer_list; 
    FILE* config_file;
    struct sv_instance_addr peer_addr;
    char sid_str[96];
    char addr_str[96];
    uint32_t capabilities = 0;
    uint32_t capacity = 0;
    uint32_t relation = 0;
    int tok_read = 0;

    //#peerSID peerAddress peerCapabilities peerCapacity peerRelation
    //first entry is always the local resolver - peerRelation = SELF
    if(!config_path) {
        return -1;
    }

    LOG_DBG("Loading config file: %s\n", config_path);
    config_file = fopen(config_path, "r");

    if(!config_file) {
        return -1;
    }

    peer_list = g_ptr_array_new();

    bzero(&peer_addr, sizeof(peer_addr));

    peer_addr.service.sv_family = AF_SERVAL;
    peer_addr.service.sv_prefix_bits = 255;
    peer_addr.address.sin.sin_family = AF_INET;

    while(fgets(line_buffer, 1024, config_file)) {
        temp = strchr(line_buffer, '#');

        if(temp) {
            temp[0] = '\0';
        }

        tok_read = sscanf(line_buffer, "%s %s %u %u %u\n", sid_str, addr_str, &capabilities,
                &capacity, &relation);

        if(tok_read == 0) {
            continue;
        }

        if(tok_read != 5) {
            LOG_DBG("Invalid peer configuration format. Expected 5 fields, parsed only %i: %s\n", tok_read, line_buffer);
        }

        //verify the input values
        if(parse_service_desc(sid_str, &peer_addr.service)) {
            //TODO error handling
        }

        if(!inet_aton(addr_str, &peer_addr.address.sin.sin_addr)) {
            //TODO error handling
        }

        if(relation > RELATION_PARENT && relation != RELATION_SELF) {

            //TODO error handling
        }

        if(relation == RELATION_SELF) {
            /* probably need special handling of m-threading for incoming resolution path and server resolver events*/
            resolver->interface->set_capabilities(resolver, capabilities);
            resolver->resolver.capacity = capacity;
            rpc_handler->def_callback.rpc->interface->set_local_address(
                    rpc_handler->def_callback.rpc, (struct sockaddr*) &peer_addr.service,
                    sizeof(struct sockaddr_sv));
        } else if((peer = resolver->interface->get_peer(resolver, &peer_addr.service.sv_srvid))) {
            /*TODO - make these functions to signal the local resolver that relations have changed?*/
            peer->resolver.relation = relation;
            peer->resolver.capabilities = capabilities;
            g_ptr_array_add(peer_list, peer);
        } else {
            peer = create_client_service_resolver(&resolver_id, &peer_addr, 0, capabilities,
                    capacity, relation);
            /*initialize and start?*/
            g_ptr_array_add(peer_list, peer);
        }
    }

    if(ferror(config_file)) {
        LOG_ERR("Error reading peer config file %s: %s\n", 
                config_path, strerror(errno));
        goto error;
    }

    /*wholesale update - stop/start the local resolver: server resolver?*/
    resolver->interface->clear_peers(resolver);

    int i = 0;
    for(i = 0; i < peer_list->len; i++) {
        peer = (service_resolver*) g_ptr_array_index(peer_list, i);

        if(peer->resolver.state == CREATED && resolver->resolver.state == ACTIVE) {
            peer->interface->initialize(peer);
            peer->interface->start(peer);
        }

        resolver->interface->peer_discovered(resolver, peer, 0);
    }

    g_ptr_array_free(peer_list, 1);
    return 0;

    error:
    /*remove the peers, if any
     */
    for(i = 0; i < peer_list->len; i++) {
        peer = (service_resolver*) g_ptr_array_index(peer_list, i);

        if(peer->resolver.state == CREATED) {
            free(peer);
        }
    }

    g_ptr_array_free(peer_list, 1);
    return -1;

}

int main(int argc, char **argv) {

    int daemon = FALSE;
    int stackid = 0;
    int capabilities = SVPF_STUB;
    char* config = NULL;
    int ret = EXIT_SUCCESS;

    initialize_signals();

    int opt = 0;
    int longind = 0;
    while((opt = getopt_long(argc, argv, "dm:c:s:", router_options, &longind)) != -1) {
        //printf("opt: %c\n", opt);
        switch(opt) {
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
            case 's':
                stackid = atoi(optarg);
                if(stackid < 0) {
                    stackid = 0;
                }
                break;
            case '?':
                break;
        }
    }
    /*command line options*/
    opt = optind;

    if(daemon) {
        LOG_DBG("Daemonizing...\n");
        ret = daemonize();

        if(ret < 0) {
            LOG_ERR("Could not daemonize\n");
            return ret;
        }
    }

    initialize_system();

    /* create the resolution path - must establish the stack-path first before binding any service IDs*/
    rpath = create_resolution_path();
    if(!rpath) {
        LOG_ERR("Could not create resolution path - stack control\n");
        terminate_system();
        exit(1);
    }

    rpath->path.stack_id = stackid;

    /*create local resolver and prototype remote(client) resolver for discovery*/
    memcpy(&resolver_id, &service_router_prefix, sizeof(service_router_prefix));
    initialize_service_id(&resolver_id.sv_srvid, resolver_id.sv_prefix_bits);
    resolver_id.sv_prefix_bits = 255;

    struct sv_instance_addr def_resolver_id;
    bzero(&def_resolver_id, sizeof(def_resolver_id));
    memcpy(&def_resolver_id.service, &service_router_prefix, sizeof(service_router_prefix));
    //def_resolver_id.service.sv_flags = SVSF_LOCAL_SCOPE | SVSF_STRICT_SCOPE;
    def_resolver_id.address.sin.sin_family = AF_INET;
    def_resolver_id.address.sin.sin_addr.s_addr = 0xFFFFFFFF;

    LOG_DBG("Generated resolver service ID: %s\n", service_id_to_str(&resolver_id.sv_srvid));

    //def_resolver = create_client_service_resolver(&resolver_id, &def_resolver_id, 0, SVPF_STUB,
    def_resolver = create_client_service_resolver(&def_resolver_id.service, &def_resolver_id, 0,
            SVPF_STUB, DEFAULT_CAPACITY, RELATION_UNKNOWN);
    /*no instance address for the default resolver*/
    if(!def_resolver) {
        LOG_ERR("Could not create default client resolver!\n");
        terminate_system();
        exit(1);
    }

    resolver = create_local_service_resolver(&resolver_id, capabilities, DEFAULT_CAPACITY,
            def_resolver, rpath);

    if(!resolver) {
        LOG_ERR("Could not create local service resolver!\n");
        terminate_system();
        exit(1);
    }

    /*add the local addresses to the resolver*/
    init_local_address_list(resolver);

    int count = resolver_get_address_count(resolver);

    int i = 0;
    struct net_addr* address;
    for(i = 0; i < count; i++) {
        address = resolver_get_address(resolver, i);
        //printf("Local resolver address: %s\n", inet_ntoa(address->net_un.un_ip));
    }

    /* create the rpc handler for receiving incoming remote requests*/
    rpc_handler = create_server_rpc_handler(resolver);

    if(!rpc_handler) {
        LOG_ERR("Could not create rpc handler!\n");
        terminate_system();
        exit(1);
    }

    /*hook the rpc handler to the def_resolver for incoming discovery messages*/
    client_get_messaging(def_resolver)->interface->set_callback(client_get_messaging(def_resolver),
            &rpc_handler->callback);

    /*the stack-path must be initialized and started prior to registering any services */
    rpath->interface->initialize(rpath);
    printf("STARTING RESOLUTION PATH\n");
    rpath->interface->start(rpath);

    /* must be initialized next since register events will trigger
     * service table insertions
     */

    resolver->interface->initialize(resolver);

    def_resolver->interface->incref(def_resolver);
    def_resolver->interface->initialize(def_resolver);

    server_rpc_handler_initialize(rpc_handler);

    /* if the config exists, load it*/
    if(config) {
        load_config(config);
    }

    /* command line capabilities overrides config */
    if(capabilities != 0) {
        rpath->interface->set_capabilities(rpath, capabilities);
    }

    printf("STARTING RESOLVERS\n");
    /* starts the service ID listening tasks*/
    def_resolver->interface->start(def_resolver);
    server_rpc_handler_start(rpc_handler);

    /*starts various local resolver tasks*/
    resolver->interface->start(resolver);


    struct timespec nap;
    bzero(&nap, sizeof(nap));
    nap.tv_sec = 10;
    int retval;
    router_running = 1;
    while(router_running) {
        retval = nanosleep(&nap, NULL);

        if(retval) {
            /*interrupted*/
            //LOG_DBG("Service router main thread interrupted: %s\n", strerror(errno));
        }
    }

    LOG_DBG("Stopping...\n");

    resolver->interface->stop(resolver);
    server_rpc_handler_stop(rpc_handler);
    def_resolver->interface->stop(def_resolver);
    rpath->interface->stop(rpath);

    LOG_DBG("Finalizing...\n");
    resolver->interface->finalize(resolver);
    server_rpc_handler_finalize(rpc_handler);
    def_resolver->interface->finalize(def_resolver);
    rpath->interface->finalize(rpath);

    terminate_system();

    LOG_DBG("Service router finished - exiting\n");

    return ret;
}
