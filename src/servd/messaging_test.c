/*
 * messaging_test.c
 *
 *  Created on: Mar 9, 2011
 *      Author: daveds
 */

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
#include "resolver_base.h"
#include "resolution_path.h"
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

#define TEST_RESOLUTION_COUNT 10
static volatile int router_running = FALSE;
static stack_t signal_stack;

extern void udp_channel_destroy();
extern void udp_channel_create();
extern void create_resolution_path(resolution_path* respath);
extern int create_udp_message_channel(struct sockaddr_sv* local, struct sv_instance_addr* remote,
        int buffer_len, message_channel_callback* callback, message_channel* channel);

static int test_register_services(void* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address, uint32_t ttl);
static int test_unregister_services(void* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address);
static int test_update_services(void* resolver, service_resolver* peer, uint16_t type,
        stat_response* responses);

static struct sv_resolver_interface test_resolver_interface = {
//eh?
        .register_services = test_register_services,
        .unregister_services = test_unregister_services,
        .update_services = test_update_services, };

static int registered = 0;
static int unregistered = 0;
static int updated = 0;
static int channel1_recv = 0;
static int channel2_recv = 0;

static message_channel channel1;
static message_channel channel2;

static int test_recv_message(void* target, const void* message, size_t length);

static message_channel_callback test_cb1 =
        { .target = &channel1, .recv_message = test_recv_message };
static message_channel_callback test_cb2 =
        { .target = &channel2, .recv_message = test_recv_message };

static int test_recv_message(void* target, const void* message, size_t length) {
    int addrlen = 0;
    if(target == &channel1) {

        LOG_DBG(
                "Receiving message for channel 1: %s of size %i\n",
                service_id_to_str(
                        &((const struct sockaddr_sv*) ((message_channel*) target)->interface->
                                get_local_address(((message_channel*) target)->target, &addrlen))->sv_srvid),
                length);
        channel1_recv++;
    } else if(target == &channel2) {
        LOG_DBG(
                "Receiving message for channel 2: %s of size %i\n",
                service_id_to_str(
                        &((const struct sockaddr_sv*) ((message_channel*) target)->interface->
                                get_local_address(((message_channel*) target)->target, &addrlen))->sv_srvid),
                length);
        channel2_recv++;
    }
    return 0;
}

static int test_register_services(void* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address, uint32_t ttl) {

    int i = 0;
    for(i = 0; i < num_svc; i++) {
        LOG_DBG("Resolution path registered service: %s with ttl %i\n", service_id_to_str(
                        &services[i].service), ttl);
    }
    registered += num_svc;
    return 0;
}

static int test_unregister_services(void* resolver, service_resolver* peer,
        struct service_desc* services, size_t num_svc, struct net_addr* address) {
    int i = 0;
    for(i = 0; i < num_svc; i++) {
        LOG_DBG("Resolution path unregistered service: %s \n", service_id_to_str(
                        &services[i].service));
    }
    unregistered += num_svc;
    return 0;
}

static int test_update_services(void* resolver, service_resolver* peer, uint16_t type,
        stat_response* responses) {
    struct sv_instance_stats* stat = NULL;

    int i = 0;
    for(i = 0; i < responses->count; i++) {
        switch(type) {
            case SVS_INSTANCE_STATS:
                stat = &((struct sv_instance_stats*) responses->data)[i];

                LOG_DBG("Resolution path services updated: %s @ %s\n", service_id_to_str(
                                &stat->service.service), inet_ntoa(stat->address.net_un.un_ip));

        }
    }
    updated += responses->count;
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

static int test_resolution_equality(struct service_resolution* test_res,
        struct service_resolution* orig_res, int count) {

    int tmatch = 0;
    int matched[count];
    bzero(matched, count * sizeof(int));
    int i, j = 0;
    for(i = 0; i < count; i++) {
        for(j = 0; j < count; j++) {
            if(memcmp(&test_res[i], &orig_res[j], sizeof(*orig_res)) == 0) {
                if(matched[j]) {
                    return 0;
                }
                matched[j]++;
                tmatch++;
                break;
            }
        }
        if(tmatch == i) {
            return 0;
        }
    }

    return 1;

}

static void create_message_channel(struct sockaddr_sv* local, struct sv_instance_addr* remote,
        message_channel* channel, message_channel_callback* cb) {

    if(create_udp_message_channel(local, remote, 0, cb, channel)) {
        LOG_ERR("Could not create resolver rpc - message channel error\n");
        return;
    }

    channel->interface->initialize(channel->target);
    channel->interface->start(channel->target);

}

static void destroy_message_channel(message_channel* channel) {
    channel->interface->stop(channel->target);
    channel->interface->finalize(channel->target);
    free(channel->target);
}

static void test_resolution_path(resolution_path* rpath) {
    int bytes_resolved = 0;
    int packets_resolved = 0;

    struct service_desc sdesc;
    bzero(&sdesc, sizeof(sdesc));
    sdesc.prefix = 255;

    /*create 2 serval udp message channels - test register*/
    struct sv_instance_addr chan1_saddr;
    bzero(&chan1_saddr, sizeof(chan1_saddr));
    chan1_saddr.service.sv_prefix_bits = 255;
    chan1_saddr.service.sv_srvid.srv_un.un_id8[0] = 255;
    chan1_saddr.service.sv_family = AF_SERVAL;
    initialize_service_id(&chan1_saddr.service.sv_srvid, 8);

    struct sv_instance_addr chan2_saddr;
    bzero(&chan2_saddr, sizeof(chan2_saddr));
    chan2_saddr.service.sv_family = AF_SERVAL;
    chan2_saddr.service.sv_prefix_bits = 255;
    chan2_saddr.service.sv_srvid.srv_un.un_id8[0] = 254;
    initialize_service_id(&chan2_saddr.service.sv_srvid, 8);

    create_message_channel(&chan1_saddr.service, &chan2_saddr, &channel1, &test_cb1);

    struct timespec stime;
    bzero(&stime, sizeof(stime));
    stime.tv_nsec = 10000000;
    stime.tv_sec = 0;

    nanosleep(&stime, NULL);
    printf("Created message channel1, registered count: %i\n", registered);
    assert(registered == 1);

    create_message_channel(&chan2_saddr.service, &chan1_saddr, &channel2, &test_cb2);

    nanosleep(&stime, NULL);
    printf("Created message channel2, registered count: %i\n", registered);
    assert(registered == 2);

    /* send packets for direct resolution to each message channel */
    struct sv_echo_message emsg;
    bzero(&emsg, sizeof(emsg));
    int xid = 1;
    init_control_header(&emsg.header, SV_ECHO_REQUEST, xid++, sizeof(emsg));
    emsg.count = 1;
    emsg.timestamp = get_current_time_ms();

    channel1.interface->send_message(channel1.target, &emsg, sizeof(emsg));
    bytes_resolved += sizeof(emsg);
    packets_resolved++;

    nanosleep(&stime, NULL);
    printf("Sent 1 packet from channel1 to channel2, received count: %i\n", channel2_recv);
    assert(channel2_recv == 1);

    struct sv_query_request rmsg;
    bzero(&rmsg, sizeof(rmsg));
    int size = sizeof(rmsg) + sizeof(chan2_saddr);
    init_control_header(&rmsg.header, SV_QUERY_REQUEST, xid++, size);

    memcpy(&sdesc.service, &chan2_saddr.service.sv_srvid, sizeof(sdesc.service));

    struct iovec msgvec[2] = { { (void*) &rmsg, sizeof(rmsg) }, { (void*) &sdesc, sizeof(sdesc) } };
    channel1.interface->send_message_iov(channel1.target, msgvec, 2, size);
    bytes_resolved += size;
    packets_resolved++;

    nanosleep(&stime, NULL);
    printf("Sent 2 packets from channel1 to channel2, received count: %i\n", channel2_recv);
    assert(channel2_recv == 2);

    bzero(&emsg, sizeof(emsg));
    init_control_header(&emsg.header, SV_ECHO_REQUEST, xid++, sizeof(emsg));
    emsg.count = 2;
    emsg.timestamp = get_current_time_ms();

    channel2.interface->send_message(channel2.target, &emsg, sizeof(emsg));
    bytes_resolved += sizeof(emsg);
    packets_resolved++;

    nanosleep(&stime, NULL);
    printf("Sent 1 packet from channel2 to channel1, received count: %i\n", channel1_recv);
    assert(channel1_recv == 1);

    bzero(&rmsg, sizeof(rmsg));
    init_control_header(&rmsg.header, SV_QUERY_REQUEST, xid++, size);
    memcpy(&sdesc.service, &chan1_saddr.service.sv_srvid, sizeof(sdesc.service));
    //msgvec[1].iov_base = (void*) &chan1_saddr;
    channel2.interface->send_message_iov(channel2.target, msgvec, 2, size);
    bytes_resolved += size;
    packets_resolved++;

    nanosleep(&stime, NULL);
    printf("Sent 2 packets from channel2 to channel1, received count: %i\n", channel1_recv);
    assert(channel1_recv == 2);

    struct service_stat srv_stats;
    bzero(&srv_stats, sizeof(srv_stats));
    int retval = rpath->interface->get_service_stats(rpath->target, &srv_stats);
    assert(retval == 0);

    printf(
            "Service stats: instances(%i) services(%i) bytes resolved(%i) packets resolved(%i) capabilities(%i)\n",
            srv_stats.instances, srv_stats.services, srv_stats.bytes_resolved,
            srv_stats.packets_resolved, srv_stats.capabilities);
    assert(srv_stats.instances == 2);
    assert(srv_stats.services == 2);
    assert(srv_stats.bytes_resolved == bytes_resolved);
    assert(((srv_stats.capabilities & SVC_TRANSIT)) == 0);
    assert(srv_stats.packets_resolved == packets_resolved);

    /*add resolutions*/
    struct service_resolution resolutions[TEST_RESOLUTION_COUNT];
    struct service_resolution_stat res_stats[TEST_RESOLUTION_COUNT];

    bzero(resolutions, TEST_RESOLUTION_COUNT * sizeof(struct service_resolution));
    bzero(res_stats, TEST_RESOLUTION_COUNT * sizeof(struct service_resolution_stat));

    bzero(&sdesc, sizeof(sdesc));
    sdesc.service.srv_un.un_id8[0] = 128;
    sdesc.flags = 0;
    sdesc.prefix = 255;

    //    struct net_addr address;
    //    bzero(&address, sizeof(address));

    char buffer[32];
    strcpy(buffer, "192.1.2.");
    int i = 0;

    for(i = 0; i < TEST_RESOLUTION_COUNT; i++) {
        initialize_service_id(&sdesc.service, 8);
        sprintf(buffer + 8, "%i", i);
        memcpy(&resolutions[i].srvid, &sdesc.service, sizeof(sdesc.service));
        resolutions[i].sv_flags = sdesc.flags;
        resolutions[i].sv_prefix_bits = sdesc.prefix;
        resolutions[i].priority = i * 100;
        resolutions[i].weight = i * 5 + 37;
        inet_aton(buffer, &resolutions[i].address.net_un.un_ip);

        memcpy(&res_stats[i].res, &resolutions[i], sizeof(*resolutions));
    }

    retval = rpath->interface->add_resolutions(rpath->target, resolutions, TEST_RESOLUTION_COUNT);

    assert(retval == 0);
    printf("Added %i resolution rules\n", TEST_RESOLUTION_COUNT);
    bzero(&sdesc, sizeof(sdesc));
    sdesc.service.srv_un.un_id8[0] = 128;
    sdesc.flags = 0;
    sdesc.prefix = 8;

    struct service_resolution* ret_res;
    retval = rpath->interface->get_resolutions(rpath->target, &sdesc, &ret_res);
    assert(retval == TEST_RESOLUTION_COUNT);

    assert(test_resolution_equality(ret_res, resolutions, retval));
    free(ret_res);

    /*modify resolutions*/
    for(i = 0; i < TEST_RESOLUTION_COUNT; i++) {
        resolutions[i].sv_flags = sdesc.flags | SVSF_DOMAIN_SCOPE;
        resolutions[i].sv_prefix_bits = sdesc.prefix;
        resolutions[i].priority = i * 100;
        resolutions[i].weight = i * 5 + 37;
        inet_aton(buffer, &resolutions[i].address.net_un.un_ip);
    }

    retval
            = rpath->interface->modify_resolutions(rpath->target, resolutions,
                    TEST_RESOLUTION_COUNT);
    assert(retval == 0);
    printf("Modified %i resolution rules\n", TEST_RESOLUTION_COUNT);

    retval = rpath->interface->get_resolutions(rpath->target, &sdesc, &ret_res);
    assert(retval == TEST_RESOLUTION_COUNT);

    assert(test_resolution_equality(ret_res, resolutions, retval));
    free(ret_res);

    /*test transit mode and get stats*/
    bzero(&srv_stats, sizeof(srv_stats));
    retval = rpath->interface->get_service_stats(rpath->target, &srv_stats);
    assert(retval == 0);
    printf(
            "Service stats: instances(%i) services(%i) bytes resolved(%i) packets resolved(%i) capabilities(%i)\n",
            srv_stats.instances, srv_stats.services, srv_stats.bytes_resolved,
            srv_stats.packets_resolved, srv_stats.capabilities);

    assert(srv_stats.instances == 12);
    assert(srv_stats.services == 12);
    assert(srv_stats.bytes_resolved == bytes_resolved);
    assert((srv_stats.capabilities & SVC_TRANSIT) == 0);
    assert(srv_stats.packets_resolved == packets_resolved);

    rpath->interface->set_transit(rpath->target, 1);
    printf("Transit mode set\n");
    bzero(&srv_stats, sizeof(srv_stats));
    retval = rpath->interface->get_service_stats(rpath->target, &srv_stats);
    assert(retval == 0);
    printf(
            "Service stats: instances(%i) services(%i) bytes resolved(%i) packets resolved(%i) capabilities(%i)\n",
            srv_stats.instances, srv_stats.services, srv_stats.bytes_resolved,
            srv_stats.packets_resolved, srv_stats.capabilities);

    assert(srv_stats.instances == 12);
    assert(srv_stats.services == 12);
    assert(srv_stats.bytes_resolved == bytes_resolved);
    assert((srv_stats.capabilities & SVC_TRANSIT) == 1);
    assert(srv_stats.packets_resolved == packets_resolved);

    /* send resolution packets */
    /*resolve in the down direction first, then in the "up" direction bouncing off of the loopback address*/
    struct sv_instance_addr instaddr;
    bzero(&instaddr, sizeof(instaddr));
    instaddr.address.sin.sin_family = AF_INET;

    for(i = 0; i < TEST_RESOLUTION_COUNT; i++) {

        memcpy(&instaddr.service.sv_srvid, &resolutions[i].srvid, sizeof(instaddr.service.sv_srvid));
        instaddr.service.sv_prefix_bits = resolutions[i].sv_prefix_bits;
        instaddr.service.sv_flags = resolutions[i].sv_flags;
        memcpy(&instaddr.address.sin.sin_addr, &resolutions[i].address.net_un.un_ip,
                sizeof(instaddr.address.sin.sin_addr));

        channel1.interface->set_peer_address(channel1.target, (struct sockaddr*) &instaddr,
                sizeof(struct sockaddr_sv));
        channel1.interface->send_message(channel1.target, &emsg, sizeof(emsg));

        bytes_resolved += sizeof(emsg);
        packets_resolved++;

        channel1.interface->set_peer_address(channel1.target, (struct sockaddr*) &instaddr,
                sizeof(struct sv_instance_addr));
        channel1.interface->send_message(channel1.target, &emsg, sizeof(emsg));

        bytes_resolved += sizeof(emsg);
        packets_resolved++;
    }

    bzero(&srv_stats, sizeof(srv_stats));
    retval = rpath->interface->get_service_stats(rpath->target, &srv_stats);
    assert(retval == 0);
    printf("Sent %i packets for resolution both output and input via loopback reflection\n", 2
            * TEST_RESOLUTION_COUNT);

    printf(
            "Service stats: instances(%i) services(%i) bytes resolved(%i) packets resolved(%i) capabilities(%i)\n",
            srv_stats.instances, srv_stats.services, srv_stats.bytes_resolved,
            srv_stats.packets_resolved, srv_stats.capabilities);

    assert(srv_stats.instances == 12);
    assert(srv_stats.services == 12);
    assert(srv_stats.bytes_resolved == bytes_resolved);
    assert((srv_stats.capabilities & SVC_TRANSIT) == 1);
    assert(srv_stats.packets_resolved == packets_resolved);

    retval = rpath->interface->remove_resolutions(rpath->target, res_stats, TEST_RESOLUTION_COUNT);
    assert(retval == 0);
    assert(updated == TEST_RESOLUTION_COUNT);

    rpath->interface->set_transit(rpath->target, 0);
    printf("Resolutions removed and transit mode disabled\n");
    /*last message sent should have been to a full instance addr - no transit allowed now
     *resolve in broadcast
     */
    //channel1.interface->send_message(channel1.target, &emsg, sizeof(emsg));

    bzero(&srv_stats, sizeof(srv_stats));
    retval = rpath->interface->get_service_stats(rpath->target, &srv_stats);
    assert(retval == 0);
    printf(
            "Service stats: instances(%i) services(%i) bytes resolved(%i) packets resolved(%i) capabilities(%i)\n",
            srv_stats.instances, srv_stats.services, srv_stats.bytes_resolved,
            srv_stats.packets_resolved, srv_stats.capabilities);

    assert(srv_stats.instances == 2);
    assert(srv_stats.services == 2);
    assert(srv_stats.bytes_resolved == bytes_resolved);
    assert((srv_stats.capabilities & SVC_TRANSIT) == 0);
    assert(srv_stats.packets_resolved == packets_resolved);

    destroy_message_channel(&channel2);
    nanosleep(&stime, NULL);
    printf("Destroyed message channel2, unregistered count %i\n", unregistered);
    assert(unregistered == 1);

    destroy_message_channel(&channel1);

    nanosleep(&stime, NULL);
    printf("Destroyed message channel1, unregistered count %i\n", unregistered);

    assert(unregistered == 0);

    bzero(&srv_stats, sizeof(srv_stats));
    retval = rpath->interface->get_service_stats(rpath->target, &srv_stats);
    assert(retval == 0);
    printf(
            "Service stats: instances(%i) services(%i) bytes resolved(%i) packets resolved(%i) capabilities(%i)\n",
            srv_stats.instances, srv_stats.services, srv_stats.bytes_resolved,
            srv_stats.packets_resolved, srv_stats.capabilities);

    assert(srv_stats.instances == 0);
    assert(srv_stats.services == 0);
    assert(srv_stats.bytes_resolved == bytes_resolved);
    assert((srv_stats.capabilities & SVC_TRANSIT) == 0);
    assert(srv_stats.packets_resolved == packets_resolved);
}

int main(int argc, char **argv) {

    int ret = EXIT_SUCCESS;

    initialize_signals();
    initialize_system();

    /* if the config exists, load it - TODO*/

    struct sockaddr_sv resolver_id;
    memcpy(&resolver_id, &service_router_prefix, sizeof(service_router_prefix));
    initialize_service_id(&resolver_id.sv_srvid, resolver_id.sv_prefix_bits);

    struct sv_base_service_resolver resolver;
    bzero(&resolver, sizeof(resolver));
    base_resolver_initialize(&resolver);

    service_resolver res = { .target = &resolver, .interface = &test_resolver_interface };

    /* create the resolution path - must register with the stack first before binding any service IDs*/
    resolution_path rpath;
    create_resolution_path(&rpath);

    rpath.interface->set_resolver(rpath.target, &res);
    rpath.interface->initialize(rpath.target);

    printf("STARTING RESOLUTION PATH\n");
    rpath.interface->start(rpath.target);

    //rpath.interface->set_transit(rpath.target, TRUE);

    test_resolution_path(&rpath);

    rpath.interface->stop(rpath.target);

    LOG_DBG("Finalizing...\n");
    rpath.interface->finalize(rpath.target);

    terminate_system();
    LOG_DBG("done\n");

    return ret;
}
