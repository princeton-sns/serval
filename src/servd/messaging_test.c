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

extern void udp_channel_destroy();
extern void udp_channel_create();
extern resolution_path* create_resolution_path();
extern message_channel* create_udp_message_channel(struct sockaddr_sv* local,
        struct sv_instance_addr* remote, int buffer_len, message_channel_callback* callback);

static int test_service_registered(resolution_path_callback* cb, struct service_desc* service);
static int test_service_unregistered(resolution_path_callback* cb, struct service_desc* service);
static int test_stat_update(resolution_path_callback* cb,
        struct service_info_stat* res_stats, size_t scount);

static resolution_path_callback test_path_callback = {
//eh?
        .service_registered = test_service_registered,
        .service_unregistered = test_service_unregistered,
        .stat_update = test_stat_update };

static volatile int router_running = FALSE;
static stack_t signal_stack;

static int registered = 0;
static int unregistered = 0;
static int updated = 0;
static int channel1_recv = 0;
static int channel2_recv = 0;

static int test_running = 0;

static message_channel* channel1;
static message_channel* channel2;

static int test_recv_message(message_channel_callback* cb, const void* message, size_t length);

static message_channel_callback test_cb1;
static message_channel_callback test_cb2;

static int test_recv_message(message_channel_callback* cb, const void* message, size_t length) {
    int addrlen = 0;
    if(cb->target == &test_cb1) {

        LOG_DBG(
                "Receiving message for channel 1: %s of size %zu\n",
                service_id_to_str(
                        &((const struct sockaddr_sv*) channel1->interface->
                                get_local_address(channel1, &addrlen))->sv_srvid),
                length);
        channel1_recv++;
    } else if(cb->target == &test_cb2) {
        LOG_DBG(
                "Receiving message for channel 2: %s of size %zu\n",
                service_id_to_str(
                        &((const struct sockaddr_sv*) channel2->interface->
                                get_local_address(channel2, &addrlen))->sv_srvid),
                length);
        channel2_recv++;
    }
    return 0;
}

static int test_service_registered(resolution_path_callback* cb, struct service_desc* service) {

    LOG_DBG("Resolution path registered service: %s\n", service_id_to_str(
                    &service->service));

    registered++;
    return 0;
}

static int test_service_unregistered(resolution_path_callback* cb, struct service_desc* service) {
    LOG_DBG("Resolution path unregistered service: %s \n", service_id_to_str(
                    &service->service));

    unregistered++;
    return 0;
}

static int test_stat_update(resolution_path_callback* cb,
        struct service_info_stat* res_stats, size_t scount) {
    struct service_info_stat* stat = NULL;

    int i = 0;
    for(i = 0; i < scount; i++) {
        stat = &res_stats[i];

        LOG_DBG("Resolution path services updated: %s @ %s\n", 
		service_id_to_str(&stat->service.srvid), 
		inet_ntoa(stat->service.address.net_un.un_ip));

    }
    updated += scount;
    return 0;
}

static void terminate_handler(int sig) {
    /*set running to 0 cleanup code*/
    printf("Terminating messagetest\n");
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

static int test_resolution_equality(struct service_info* test_res,
        struct service_info* orig_res, int count) {

    int tmatch = 0;
    int matched[count];
    bzero(matched, count * sizeof(int));
    int i, j = 0;
    for(i = 0; i < count; i++) {
        for(j = 0; j < count; j++) {
            if(memcmp(&test_res[i], &orig_res[j], sizeof(*orig_res)) == 0) {
                if(matched[j]) {
                    printf("res already matched! test %s orig %s\n", service_id_to_str(
                            &test_res->srvid), service_id_to_str(&orig_res->srvid));
                    return 0;
                }
                matched[j]++;
                tmatch++;
                break;
            }
        }
        if(tmatch == i) {
            printf(
                    "Could not match test res: %s prefix: %i flags: %i addr: %i weight: %i priority: %i\n",
                    service_id_to_str(&test_res->srvid), test_res->srvid_prefix_bits,
                    test_res->srvid_flags, test_res->address.net_un.un_ip.s_addr, test_res->weight,
                    test_res->priority);
            return 0;
        }
    }

    return 1;

}

static message_channel* create_message_channel(struct sockaddr_sv* local,
        struct sv_instance_addr* remote, message_channel_callback* cb) {
    message_channel* channel = NULL;
    if(!(channel = create_udp_message_channel(local, remote, 0, cb))) {
        LOG_ERR("Could not create resolver rpc - message channel error\n");
        return NULL;
    }

    channel->interface->initialize(channel);
    channel->interface->start(channel);

    return channel;
}

static void destroy_message_channel(message_channel* channel) {
    channel->interface->stop(channel);
    channel->interface->finalize(channel);
    free(channel);
}

static int thread_sleep(int ms) {
    struct timespec nap;
    struct timespec rnap;

    bzero(&nap, sizeof(nap));
    bzero(&rnap, sizeof(rnap));

    nap.tv_sec = ms / 1000;
    nap.tv_nsec = (ms % 1000) * 1000000;

    int elapsed = 0;
    //printf("Sleeping for %i ms\n", ms);
    while(rnap.tv_sec >= 0 && rnap.tv_nsec >= 0 && nanosleep(&nap, &rnap)) {

        nap.tv_sec -= rnap.tv_sec;

        if(rnap.tv_nsec > nap.tv_nsec) {
            nap.tv_sec--;

            nap.tv_nsec += (1000000000 - rnap.tv_nsec);
        } else {
            nap.tv_nsec -= rnap.tv_nsec;
        }

        elapsed += ((nap.tv_sec * 1000) + (nap.tv_nsec / 1000000));
        nap = rnap;
        //LOG_ERR("Sleep interrupted! elapsed: %i New sleep: %i.%09li\n", elapsed, (int) nap.tv_sec, nap.tv_nsec);

    }

    elapsed += ((nap.tv_sec * 1000) + (nap.tv_nsec / 1000000));
    //printf("time elapsed during sleep: %i.%09i elapsed total: %i\n", nap.tv_sec, nap.tv_nsec,
    //        elapsed);

    return elapsed;
}
static void test_resolution_path(void* data) {
    resolution_path* rpath = (resolution_path*) data;
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

    test_cb1.target = &test_cb1;
    test_cb1.recv_message = test_recv_message;

    test_cb2.target = &test_cb2;
    test_cb2.recv_message = test_recv_message;

    channel1 = create_message_channel(&chan1_saddr.service, &chan2_saddr, &test_cb1);

    thread_sleep(100);
    printf("Created message channel1, registered count: %i\n", registered);
    assert(registered == 1);

    channel2 = create_message_channel(&chan2_saddr.service, &chan1_saddr, &test_cb2);

    thread_sleep(100);
    printf("Created message channel2, registered count: %i\n", registered);
    assert(registered == 2);

    /* send packets for direct resolution to each message channel */
    struct sv_echo_message emsg;
    bzero(&emsg, sizeof(emsg));
    int xid = 1;
    init_control_header(&emsg.header, SV_ECHO_REQUEST, xid++, sizeof(emsg));
    emsg.count = 1;
    emsg.timestamp = get_current_time_ms();

    printf("sending first message at: %lli\n", get_current_time_ms());
    channel1->interface->send_message(channel1, &emsg, sizeof(emsg));
    bytes_resolved += sizeof(emsg);
    packets_resolved++;

    thread_sleep(100);
    printf("waking up at: %lli\n", get_current_time_ms());
    printf("Sent 1 packet from channel1 to channel2, received count: %i\n", channel2_recv);
    assert(channel2_recv == 1);

    struct sv_query_request* rmsg;
    int size = sizeof(*rmsg) + sizeof(struct service_desc);
    rmsg = (struct sv_query_request*) malloc(size);
    bzero(rmsg, size);
    init_control_header(&rmsg->header, SV_QUERY_REQUEST, xid++, size);
    //memcpy(&rmsg->service_ids[0].service, &chan2_saddr.service.sv_srvid, sizeof(struct service_desc));
    memcpy(&sdesc.service, &chan2_saddr.service.sv_srvid, sizeof(sdesc.service));
    struct iovec msgvec[2] = { { (void*) rmsg, sizeof(*rmsg) }, { (void*) &sdesc, sizeof(sdesc) } };
    channel1->interface->send_message_iov(channel1, msgvec, 2, size);
    //channel1->interface->send_message(channel1, rmsg, size);
    bytes_resolved += size;
    packets_resolved++;

    thread_sleep(100);
    printf("Sent 2 packets from channel1 to channel2, received count: %i\n", channel2_recv);
    assert(channel2_recv == 2);

    bzero(&emsg, sizeof(emsg));
    init_control_header(&emsg.header, SV_ECHO_REQUEST, xid++, sizeof(emsg));
    emsg.count = 2;
    emsg.timestamp = get_current_time_ms();

    channel2->interface->send_message(channel2, &emsg, sizeof(emsg));
    bytes_resolved += sizeof(emsg);
    packets_resolved++;

    thread_sleep(100);
    printf("Sent 1 packet from channel2 to channel1, received count: %i\n", channel1_recv);
    assert(channel1_recv == 1);

    bzero(rmsg, size);
    init_control_header(&rmsg->header, SV_QUERY_REQUEST, xid++, size);
    //memcpy(&rmsg->service_ids[0].service, &chan1_saddr.service.sv_srvid, sizeof(struct service_desc));
    memcpy(&sdesc.service, &chan1_saddr.service.sv_srvid, sizeof(sdesc.service));
    channel2->interface->send_message_iov(channel2, msgvec, 2, size);
    //channel2->interface->send_message(channel2, rmsg, size);
    bytes_resolved += size;
    packets_resolved++;

    thread_sleep(100);
    printf("Sent 2 packets from channel2 to channel1, received count: %i\n", channel1_recv);
    assert(channel1_recv == 2);

    free(rmsg);

    struct service_stat srv_stats;
    bzero(&srv_stats, sizeof(srv_stats));
    int retval = rpath->interface->get_service_stats(rpath, &srv_stats);
    assert(retval == 0);

    printf(
            "Service stats: instances(%i) services(%i) bytes resolved(%i) packets resolved(%i) capabilities(%i)\n",
            srv_stats.instances, srv_stats.services, srv_stats.bytes_resolved,
            srv_stats.packets_resolved, srv_stats.capabilities);

    printf("expected bytes: %i packets: %i\n", bytes_resolved, packets_resolved);
    assert(srv_stats.instances == 3);
    assert(srv_stats.services == 3);
    assert(srv_stats.bytes_resolved == bytes_resolved);
    assert(((srv_stats.capabilities & SVC_TRANSIT)) == 0);
    assert(srv_stats.packets_resolved == packets_resolved);

    /*add resolutions*/
    struct service_info resolutions[TEST_RESOLUTION_COUNT];
    struct service_info_stat res_stats[TEST_RESOLUTION_COUNT];

    bzero(resolutions, TEST_RESOLUTION_COUNT * sizeof(struct service_info));
    bzero(res_stats, TEST_RESOLUTION_COUNT * sizeof(struct service_info_stat));

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
        sprintf(buffer + 8, "%i", i + 1);
        memcpy(&resolutions[i].srvid, &sdesc.service, sizeof(sdesc.service));
        resolutions[i].srvid_flags = sdesc.flags;
        resolutions[i].srvid_prefix_bits = sdesc.prefix;
        resolutions[i].priority = i * 100;
        resolutions[i].weight = i * 5 + 37;
        inet_aton(buffer, &resolutions[i].address.net_un.un_ip);

        printf("Initialized res %i: %s addr(%s %u) flags(%i) prefix(%i) priority(%i) weight(%i)\n",
                i, service_id_to_str(&resolutions[i].srvid), buffer,
                resolutions[i].address.net_un.un_ip.s_addr, resolutions[i].srvid_flags,
                resolutions[i].srvid_prefix_bits, resolutions[i].priority, resolutions[i].weight);

        memcpy(&res_stats[i].service, &resolutions[i], sizeof(*resolutions));
    }

    retval = rpath->interface->add_resolutions(rpath, resolutions, TEST_RESOLUTION_COUNT);

    assert(retval > 0);
    printf("Added %i resolution rules\n", TEST_RESOLUTION_COUNT);
    bzero(&sdesc, sizeof(sdesc));
    sdesc.service.srv_un.un_id8[0] = 128;
    sdesc.flags = 0;
    sdesc.prefix = 8;

    struct service_info* ret_res;

    for(i = 0; i < TEST_RESOLUTION_COUNT; i++) {
        memcpy(&sdesc.service, &resolutions[i].srvid, sizeof(sdesc.service));
        sdesc.prefix = resolutions[i].srvid_prefix_bits;

        //        printf("Initialized res %i: %s addr(%s %u) flags(%i) prefix(%i) priority(%i) weight(%i)\n",
        //                i, service_id_to_str(&resolutions[i].srvid), buffer,
        //                resolutions[i].address.net_un.un_ip.s_addr, resolutions[i].sv_flags,
        //                resolutions[i].srvid_prefix_bits, resolutions[i].priority, resolutions[i].weight);

        retval = rpath->interface->get_resolutions(rpath, &sdesc, &ret_res);
        assert(retval == 1);
        assert(test_resolution_equality(ret_res, &resolutions[i], retval));
        free(ret_res);
    }

    /*modify resolutions*/
    for(i = 0; i < TEST_RESOLUTION_COUNT; i++) {
        resolutions[i].srvid_flags = sdesc.flags | SVSF_DOMAIN_SCOPE;
        //resolutions[i].srvid_prefix_bits = sdesc.prefix;
        resolutions[i].priority = i * 1000 + 5;
        resolutions[i].weight = i * 3 + 11;

        printf("Modified res %i: %s addr(%s %u) flags(%i) prefix(%i) priority(%i) weight(%i)\n", i,
                service_id_to_str(&resolutions[i].srvid), buffer,
                resolutions[i].address.net_un.un_ip.s_addr, resolutions[i].srvid_flags,
                resolutions[i].srvid_prefix_bits, resolutions[i].priority, resolutions[i].weight);

        //inet_aton(buffer, &resolutions[i].address.net_un.un_ip);
    }

    retval = rpath->interface->modify_resolutions(rpath, resolutions, TEST_RESOLUTION_COUNT);
    assert(retval > 0);
    printf("Modified %i resolution rules\n", TEST_RESOLUTION_COUNT);

    for(i = 0; i < TEST_RESOLUTION_COUNT; i++) {
        memcpy(&sdesc.service, &resolutions[i].srvid, sizeof(sdesc.service));
        sdesc.prefix = resolutions[i].srvid_prefix_bits;

        //        printf("Initialized res %i: %s addr(%s %u) flags(%i) prefix(%i) priority(%i) weight(%i)\n",
        //                i, service_id_to_str(&resolutions[i].srvid), buffer,
        //                resolutions[i].address.net_un.un_ip.s_addr, resolutions[i].srvid_flags,
        //                resolutions[i].srvid_prefix_bits, resolutions[i].priority, resolutions[i].weight);

        retval = rpath->interface->get_resolutions(rpath, &sdesc, &ret_res);
        assert(retval == 1);
        assert(test_resolution_equality(ret_res, &resolutions[i], retval));
        free(ret_res);
    }

    /*test transit mode and get stats*/
    bzero(&srv_stats, sizeof(srv_stats));
    retval = rpath->interface->get_service_stats(rpath, &srv_stats);
    assert(retval == 0);
    printf(
            "Service stats: instances(%i) services(%i) bytes resolved(%i) packets resolved(%i) capabilities(%i)\n",
            srv_stats.instances, srv_stats.services, srv_stats.bytes_resolved,
            srv_stats.packets_resolved, srv_stats.capabilities);

    assert(srv_stats.instances == 13);
    assert(srv_stats.services == 13);
    assert(srv_stats.bytes_resolved == bytes_resolved);
    assert((srv_stats.capabilities & SVC_TRANSIT) == 0);
    assert(srv_stats.packets_resolved == packets_resolved);

    rpath->interface->set_capabilities(rpath, SVC_TRANSIT);
    printf("Transit mode set\n");
    bzero(&srv_stats, sizeof(srv_stats));
    retval = rpath->interface->get_service_stats(rpath, &srv_stats);
    assert(retval == 0);
    printf(
            "Service stats: instances(%i) services(%i) bytes resolved(%i) packets resolved(%i) capabilities(%i)\n",
            srv_stats.instances, srv_stats.services, srv_stats.bytes_resolved,
            srv_stats.packets_resolved, srv_stats.capabilities);

    assert(srv_stats.instances == 13);
    assert(srv_stats.services == 13);
    assert(srv_stats.bytes_resolved == bytes_resolved);
    assert((srv_stats.capabilities & SVC_TRANSIT) == 1);
    assert(srv_stats.packets_resolved == packets_resolved);

    /* send resolution packets */
    /*resolve in the down direction first, then in the "up" direction bouncing off of the loopback address*/
    struct sv_instance_addr instaddr;
    bzero(&instaddr, sizeof(instaddr));
    instaddr.address.sin.sin_family = AF_INET;
    instaddr.service.sv_family = AF_SERVAL;

    for(i = 0; i < TEST_RESOLUTION_COUNT; i++) {

        memcpy(&instaddr.service.sv_srvid, &resolutions[i].srvid, sizeof(instaddr.service.sv_srvid));
        instaddr.service.sv_prefix_bits = resolutions[i].srvid_prefix_bits;
        instaddr.service.sv_flags = resolutions[i].srvid_flags;
        memcpy(&instaddr.address.sin.sin_addr, &resolutions[i].address.net_un.un_ip,
                sizeof(instaddr.address.sin.sin_addr));

        channel1->interface->set_peer_address(channel1, (struct sockaddr*) &instaddr,
                sizeof(struct sockaddr_sv));
        channel1->interface->send_message(channel1, &emsg, sizeof(emsg));

        bytes_resolved += sizeof(emsg);
        packets_resolved++;

        channel1->interface->set_peer_address(channel1, (struct sockaddr*) &instaddr,
                sizeof(struct sv_instance_addr));
        channel1->interface->send_message(channel1, &emsg, sizeof(emsg));

        //bytes_resolved += sizeof(emsg);
        //packets_resolved++;
    }

    thread_sleep(100);
    bzero(&srv_stats, sizeof(srv_stats));
    retval = rpath->interface->get_service_stats(rpath, &srv_stats);
    assert(retval == 0);
    printf("Sent %i packets for resolution both output and input via loopback reflection\n", 2
            * TEST_RESOLUTION_COUNT);

    printf(
            "Service stats: instances(%i) services(%i) bytes resolved(%i) packets resolved(%i) capabilities(%i)\n",
            srv_stats.instances, srv_stats.services, srv_stats.bytes_resolved,
            srv_stats.packets_resolved, srv_stats.capabilities);

    assert(srv_stats.instances == 13);
    assert(srv_stats.services == 13);
    assert(srv_stats.bytes_resolved == bytes_resolved);
    assert((srv_stats.capabilities & SVC_TRANSIT) == 1);
    assert(srv_stats.packets_resolved == packets_resolved);

    retval = rpath->interface->remove_resolutions(rpath, res_stats, TEST_RESOLUTION_COUNT);

    assert(retval > 0);
    updated = 0;

    thread_sleep(100);
    assert(updated == TEST_RESOLUTION_COUNT);

    rpath->interface->set_capabilities(rpath, 0);
    printf("Resolutions removed and transit mode disabled\n");
    /*last message sent should have been to a full instance addr - no transit allowed now
     *resolve in broadcast
     */
    //channel1.interface->send_message(channel1.target, &emsg, sizeof(emsg));

    bzero(&srv_stats, sizeof(srv_stats));
    retval = rpath->interface->get_service_stats(rpath, &srv_stats);
    assert(retval == 0);
    printf(
            "Service stats: instances(%i) services(%i) bytes resolved(%i) packets resolved(%i) capabilities(%i)\n",
            srv_stats.instances, srv_stats.services, srv_stats.bytes_resolved,
            srv_stats.packets_resolved, srv_stats.capabilities);

    assert(srv_stats.instances == 3);
    assert(srv_stats.services == 3);
    assert(srv_stats.bytes_resolved == bytes_resolved);
    assert((srv_stats.capabilities & SVC_TRANSIT) == 0);
    assert(srv_stats.packets_resolved == packets_resolved);

    destroy_message_channel(channel2);
    thread_sleep(100);
    printf("Destroyed message channel2, unregistered count %i\n", unregistered);
    assert(unregistered == 1);

    bzero(&srv_stats, sizeof(srv_stats));
    retval = rpath->interface->get_service_stats(rpath, &srv_stats);
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

    destroy_message_channel(channel1);

    thread_sleep(100);
    printf("Destroyed message channel1, unregistered count %i\n", unregistered);

    assert(unregistered == 2);

    bzero(&srv_stats, sizeof(srv_stats));
    retval = rpath->interface->get_service_stats(rpath, &srv_stats);
    assert(retval == 0);
    printf(
            "Service stats: instances(%i) services(%i) bytes resolved(%i) packets resolved(%i) capabilities(%i)\n",
            srv_stats.instances, srv_stats.services, srv_stats.bytes_resolved,
            srv_stats.packets_resolved, srv_stats.capabilities);

    assert(srv_stats.instances == 1);
    assert(srv_stats.services == 1);
    assert(srv_stats.bytes_resolved == bytes_resolved);
    assert((srv_stats.capabilities & SVC_TRANSIT) == 0);
    assert(srv_stats.packets_resolved == packets_resolved);

    test_running = 0;
}

/* TODO - does the "data" for a task need to be heap allocated?*/
static resolution_path* rpath;

int main(int argc, char **argv) {

    int ret = EXIT_SUCCESS;

    initialize_signals();
    initialize_system();

    /* if the config exists, load it - TODO*/

    //struct sockaddr_sv resolver_id;
    //memcpy(&resolver_id, &service_router_prefix, sizeof(service_router_prefix));
    //initialize_service_id(&resolver_id.sv_srvid, resolver_id.sv_prefix_bits);

    /* create the resolution path - must register with the stack first before binding any service IDs*/
    rpath = create_resolution_path();

    test_path_callback.target = rpath;
    rpath->interface->set_path_callback(rpath, &test_path_callback);
    rpath->interface->initialize(rpath);

    printf("STARTING RESOLUTION PATH\n");
    rpath->interface->start(rpath);

    /* TODO - somewhat sucky requirement that we must run code in a task context
     * otherwise, things like task_cond_wait won't work
     */
    test_running = 1;

    task_add(rpath, test_resolution_path);

    struct timespec nap;
    bzero(&nap, sizeof(nap));
    nap.tv_sec = 1;

    //int retval;
    while(test_running) {
        nanosleep(&nap, NULL);
    }

    LOG_DBG("Stopping test...\n");

    rpath->interface->stop(rpath);

    LOG_DBG("Finalizing...\n");
    rpath->interface->finalize(rpath);

    free(rpath);
    terminate_system();
    LOG_DBG("done\n");

    return ret;
}
