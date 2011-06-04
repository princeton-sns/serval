/*
 * util_test.c
 *
 *  Created on: Mar 9, 2011
 *      Author: daveds
 */

/* test the time facility*/

#include "time_util.h"
#include "debug.h"
#include "service_types.h"
#include "service_util.h"
#include <assert.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

#ifndef FALSE
#define FALSE 0
#define TRUE 1

#endif

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

static void* test_time(void* data) {
    /*schedule every second*/
    long long int ctime = get_current_time_ms();
    int elapsed = 0;
    printf("Initial time: %llu\n", ctime);

    /*first check: 50 ms should be the same*/

    elapsed += thread_sleep(50);

    long long int ntime = get_current_time_ms();

    assert(ntime == ctime);
    printf("Time after %i (50 ms): %llu\n", elapsed, ctime);

    /*give it 1.05 s*/
    elapsed += thread_sleep(1050);
    ntime = get_current_time_ms();
    assert(ntime - ctime > 0);

    ctime = ntime;
    printf("Time after %i (1100 ms): %llu\n", elapsed, ctime);

    /* rev up the avg resolutions/tick */
    int i = 0;
    for(; i < 300; i++) {
        elapsed += thread_sleep(1);
        ntime = get_current_time_ms();
        assert(ntime == ctime);
    }

    printf("Time after %i (1400ms): %llu\n", elapsed, ctime);

    elapsed += thread_sleep(1000);

    printf("Time after %i (2400ms): %llu\n", elapsed, ctime);
    ntime = get_current_time_ms();
    assert(ntime - ctime > 0);

    /* slow it down */
    elapsed += thread_sleep(5000);
    ntime = get_current_time_ms();
    assert(ntime - ctime > 0);

    printf("Time after %i (7400ms): %llu\n", elapsed, ctime);

    return NULL;
}

static void test_time_full(int threaded) {

    init_time(1000);

    if(threaded) {
        void* retval;
        pthread_t threads[3];

        int i = 0;
        for(; i < 3; i++) {
            pthread_create(&threads[i], NULL, test_time, NULL);
            printf("starting thread: %i %i\n", i, (int) threads[i]);

        }
        //test_time();

        thread_sleep(10000);

        for(i = 0; i < 3; i++) {
            printf("joining thread: %i\n", i);
            pthread_join(threads[i], &retval);
        }
    } else {
        test_time(NULL);
    }
}

static void test_service_utils() {

    /*test service id init - use service_resolver_prefix as a start */
    struct sockaddr_sv resolver_id;
    memcpy(&resolver_id, &service_router_prefix, sizeof(service_router_prefix));

    printf("default service router prefix of len %i: %s\n", service_router_prefix.sv_prefix_bits,
            service_id_to_str(&service_router_prefix.sv_srvid));

    initialize_service_id(&resolver_id.sv_srvid, resolver_id.sv_prefix_bits);

    printf("initialized service router id: %s\n", service_id_to_str(&resolver_id.sv_srvid));

    int i = 0;
    for(; i < resolver_id.sv_prefix_bits / 8; i++) {
        assert(resolver_id.sv_srvid.srv_un.un_id8[i] == service_router_prefix.sv_srvid.srv_un.un_id8[i]);
    }
    uint32_t total_val = 0;
    for(i = resolver_id.sv_prefix_bits / 8 + (resolver_id.sv_prefix_bits % 8 > 0 ? 1 : 0); i < 32; i++) {
        total_val += resolver_id.sv_srvid.srv_un.un_id8[i];
    }

    assert(total_val > 0);

    /*test resolution and description from reference*/
    struct service_reference sref;
    sref.instance.address.sin.sin_addr.s_addr = 123456789;
    memcpy(&sref.instance.service, &resolver_id, sizeof(resolver_id));
    sref.capacity = 15;
    sref.priority = 7;
    sref.ttl = 3;
    sref.idle_timeout = 1001201;
    sref.hard_timeout = 86400;

    struct service_resolution sres;

    init_resolution_from_reference(&sres, &sref);

    printf("resolution sid: %s\n", service_id_to_str(&sres.srvid));
    printf("refereince sid: %s\n", service_id_to_str(&sref.instance.service.sv_srvid));
    assert(sres.address.net_un.un_ip.s_addr == sref.instance.address.sin.sin_addr.s_addr);
    assert(memcmp(&sres.srvid, &sref.instance.service.sv_srvid, sizeof(struct service_id)) == 0);
    assert(sres.sv_prefix_bits == sref.instance.service.sv_prefix_bits);
    assert(sres.sv_flags== sref.instance.service.sv_flags);
    assert(sres.priority == sref.priority);

    assert(sres.idle_timeout == sref.idle_timeout);
    assert(sres.hard_timeout == sref.hard_timeout);
    assert(sres.weight == sref.weight);

    struct service_desc sdesc;

    init_description_from_reference(&sdesc, &sref);

    assert(memcmp(&sdesc.service, &sref.instance.service.sv_srvid, sizeof(struct service_id)) == 0);
    assert(sdesc.prefix== sref.instance.service.sv_prefix_bits);
    assert(sdesc.flags== sref.instance.service.sv_flags);

    total_val = service_id_prefix_hash(&resolver_id.sv_srvid);
    assert(total_val == service_id_prefix_hash(&sdesc.service));

    resolver_id.sv_prefix_bits = SERVICE_HASH_PREFIX;
    initialize_service_id(&resolver_id.sv_srvid, SERVICE_HASH_PREFIX);

    total_val = service_id_prefix_hash(&resolver_id.sv_srvid);
    assert(total_val == service_id_prefix_hash(&sdesc.service));

    /* some way of testing the hash over a whole set?*/
    assert(service_id_prefix_equal(&resolver_id.sv_srvid, &sdesc.service));

    /*test out the bit init*/

    for(i = 0; i < 256; i++) {
        resolver_id.sv_prefix_bits = i;
        initialize_service_id(&resolver_id.sv_srvid, resolver_id.sv_prefix_bits);
        assert(!service_id_prefix_equal(&resolver_id.sv_srvid, &sdesc.service));
    }

    /*test bit string equality*/
    bzero(&sdesc, sizeof(sdesc));
    sdesc.service.srv_un.un_id8[0] = 0x98;

    bzero(&sref, sizeof(sref));
    sref.instance.service.sv_srvid.srv_un.un_id8[0] = 0x98;
    sref.instance.service.sv_srvid.srv_un.un_id8[1] = 0xFF;
    int j = 0;

    for(i = 0; i < 8; i++) {
        for(j = 0; i + j < 16; j++) {
            if(i + j <= 8) {
                assert(is_bitstring_equal(sdesc.service.srv_un.un_id8, sref.instance.service.sv_srvid.srv_un.un_id8,i,j));
            } else {
                assert(!is_bitstring_equal(sdesc.service.srv_un.un_id8, sref.instance.service.sv_srvid.srv_un.un_id8,i,j));
            }
        }
    }

    memcpy(&sdesc.service, &resolver_id.sv_srvid, sizeof(struct service_id));
    initialize_service_id(&resolver_id.sv_srvid, 128);

    /*ensure that bit 129 differs*/
    resolver_id.sv_srvid.srv_un.un_id8[16] = ~sdesc.service.srv_un.un_id8[16];

    printf("original service router id: %s\n", service_id_to_str(&sdesc.service));
    printf("128+ randomized service router id: %s\n", service_id_to_str(&resolver_id.sv_srvid));

    uint16_t longest;
    for(i = 0; i < 128; i++) {
        assert(is_bitstring_equal(sdesc.service.srv_un.un_id8, resolver_id.sv_srvid.srv_un.un_id8, i, 128 - i));
        for(j = 0; j <= 32; j++) {
            if(i + j <= 128) {
                assert(is_bitstring_equal(sdesc.service.srv_un.un_id8, resolver_id.sv_srvid.srv_un.un_id8, i,j));
            } else {
                assert(!is_bitstring_equal(sdesc.service.srv_un.un_id8, resolver_id.sv_srvid.srv_un.un_id8, i,j));
            }
        }

        assert(find_longest_common_prefix(sdesc.service.srv_un.un_id8, resolver_id.sv_srvid.srv_un.un_id8, i, 256 - i) == (128 - i));

        longest = find_longest_common_prefix(sdesc.service.srv_un.un_id8,
                resolver_id.sv_srvid.srv_un.un_id8, i, 128 - i);
        printf("longest common prefix from offset: %u to len: %u bits: %u\n", i, 128 - i, longest);
        assert(longest == (128 - i));

        longest = find_longest_common_prefix(sdesc.service.srv_un.un_id8,
                resolver_id.sv_srvid.srv_un.un_id8, i, (i + 8 > 128 ? 128 - i : 8));
        printf("longest common prefix from offset: %u to len: %u bits: %u\n", i, (i + 8 > 128 ? 128
                - i : 8), longest);
        assert(longest == (i + 8 > 128 ? 128 - i : 8));

    }

    /*byte boundary*/
    assert(find_longest_common_prefix(sdesc.service.srv_un.un_id8, resolver_id.sv_srvid.srv_un.un_id8, 124, 4) == 4);
    assert(find_longest_common_prefix(sdesc.service.srv_un.un_id8, resolver_id.sv_srvid.srv_un.un_id8, 4, 128) == 124);

    for(i = 16; i < 32; i++) {
        resolver_id.sv_srvid.srv_un.un_id8[i] = ~sdesc.service.srv_un.un_id8[i];
    }

    for(i = 128; i < 256; i++) {
        assert(!find_longest_common_prefix(sdesc.service.srv_un.un_id8, resolver_id.sv_srvid.srv_un.un_id8, i, 256 - i));
        assert(!find_longest_common_prefix(sdesc.service.srv_un.un_id8, resolver_id.sv_srvid.srv_un.un_id8, i, (i + 8 > 256? 256 - i : 8)));
    }

    /*bit value test*/
    resolver_id.sv_srvid.srv_un.un_id8[0] = 0x55;
    resolver_id.sv_srvid.srv_un.un_id8[1] = 0x55;
    int vals[9] = { 0, 1, 2, 5, 10, 21, 42, 85, 170 };

    for(i = 0; i < 8; i++) {
        for(j = 1; j <= 8; j++) {
            longest = extract_bit_value(i, j, resolver_id.sv_srvid.srv_un.un_id8);
            printf("bit value: %u for pos: %u len: %u\n", longest, i, j);

            if(i % 2 == 0) {
                assert(longest == vals[j - 1]);
            } else {
                assert(longest == vals[j]);
            }
        }
    }

}

int main(int argc, char **argv) {
    int opt;
    int threaded = FALSE;
    while((opt = getopt(argc, argv, "t")) != -1) {
        //printf("opt: %c\n", opt);
        switch(opt) {
            case 't':
                threaded = TRUE;
                break;
            case '?':
                break;
        }
    }
    /*command line options*/
    opt = optind;
    init_rand(time(NULL));

    test_service_utils();
    test_time_full(threaded);
    return 0;
}
