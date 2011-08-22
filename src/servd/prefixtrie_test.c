/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * prefixtrietest.c
 *
 *  Created on: Mar 7, 2011
 *      Author: daveds
 */
#include <assert.h>
#include "prefixtrie.h"
#include "service_util.h"
#include "service_types.h"

#define MAX_SERVICE_ID 1024

static struct sockaddr_sv services[MAX_SERVICE_ID];
static int longest_matching_sid[MAX_SERVICE_ID];

static int spec_service_ids() {
    int limit = 44;
    bzero(services, sizeof(struct service_id) * MAX_SERVICE_ID);
    int i = 0;
    for(i = 0; i < MAX_SERVICE_ID; i++) {
        longest_matching_sid[i] = -1;
        services[i].sv_prefix_bits = 200;
    }

    /*only initialize what we need*/

    /*fill in the root first*/
    for(i = 0; i < 16; i++) {
        services[i].sv_srvid.srv_un.un_id8[0] = i << 4;
    }

    /*create the doubling set
     */

    for(i = 16; i < 35; i++) {
        services[i].sv_srvid.srv_un.un_id8[0] = 0x58;
    }

    services[17].sv_srvid.srv_un.un_id8[1] = 0xF0;
    /*insert should double 2->4*/
    services[18].sv_srvid.srv_un.un_id8[1] = 0xB0;
    services[19].sv_srvid.srv_un.un_id8[1] = 0x20;
    /*insert should double 4->8*/
    services[20].sv_srvid.srv_un.un_id8[1] = 0xD0;

    services[21].sv_srvid.srv_un.un_id8[1] = 0xFF;
    /*insert should double child 2->4*/
    services[22].sv_srvid.srv_un.un_id8[1] = 0xE0;
    services[23].sv_srvid.srv_un.un_id8[1] = 0x10;
    services[24].sv_srvid.srv_un.un_id8[1] = 0x40;
    /*insert should double 8-16*/
    services[25].sv_srvid.srv_un.un_id8[1] = 0x60;

    services[26].sv_srvid.srv_un.un_id8[1] = 0x31;
    services[27].sv_srvid.srv_un.un_id8[1] = 0x52;
    services[28].sv_srvid.srv_un.un_id8[1] = 0x73;

    /*on the interstitial node doubling, this should be in slot 18 not 19*/
    services[29].sv_srvid.srv_un.un_id8[1] = 0x98;
    services[29].sv_prefix_bits = 12;

    /*split to a full node with 0xD0*/
    services[30].sv_srvid.srv_un.un_id8[1] = 0xD8;

    /*interstitial insert and removal - should be in the 0xC0 slot*/
    services[31].sv_srvid.srv_un.un_id8[1] = 0xD0;
    services[31].sv_prefix_bits = 11;

    /*should cause a node doubling - and note that it should be in a 0x80 slot given the prefix bits*/
    services[32].sv_srvid.srv_un.un_id8[1] = 0xA0;
    services[32].sv_prefix_bits = 10;

    /*should be a prefix of 0x00*/
    services[33].sv_srvid.srv_un.un_id8[1] = 0x30;
    services[33].sv_prefix_bits = 9;

    /*causes 0xA0 interstitial to become a prefix of 0x80 - 200*/
    services[34].sv_srvid.srv_un.un_id8[1] = 0x80;

    /*node prefix off 0x58 - 0x59 - prefix len = 7*/
    services[35].sv_srvid.srv_un.un_id8[0] = 0x59;
    services[35].sv_prefix_bits = 7;

    /*prefix of a prefix 0x5A*/
    services[36].sv_srvid.srv_un.un_id8[0] = 0x5A;
    services[36].sv_prefix_bits = 6;

    /*prefix insert and inheritance*/
    for(i = 37; i < 43; i++) {
        services[i].sv_srvid.srv_un.un_id8[0] = 0x9C;
    }

    services[38].sv_srvid.srv_un.un_id8[1] = 0x08;
    /*insert should double 2->4*/
    services[39].sv_srvid.srv_un.un_id8[1] = 0x08;
    services[39].sv_srvid.srv_un.un_id8[2] = 0x51;
    services[39].sv_prefix_bits = 16;

    services[40].sv_srvid.srv_un.un_id8[1] = 0x08;
    services[40].sv_srvid.srv_un.un_id8[2] = 0x62;
    services[40].sv_prefix_bits = 14;

    services[41].sv_srvid.srv_un.un_id8[1] = 0x30;
    services[41].sv_prefix_bits = 10;

    services[42].sv_srvid.srv_un.un_id8[1] = 0x70;
    services[42].sv_prefix_bits = 9;

    /*node prefix - 0x9D - 7 bits*/
    services[43].sv_srvid.srv_un.un_id8[0] = 0x9D;
    services[43].sv_prefix_bits = 7;

    int longest = 0;

    int j = 0;
    for(i = 0; i < limit; i++) {
        for(j = i + 1; j < limit; j++) {
            longest = find_longest_common_prefix(services[i].sv_srvid.srv_un.un_id8,
                    services[j].sv_srvid.srv_un.un_id8, 0, services[i].sv_prefix_bits);

            if(longest >= services[j].sv_prefix_bits && services[j].sv_prefix_bits
                    > services[longest_matching_sid[i]].sv_prefix_bits) {
                longest_matching_sid[i] = j;
            }
        }
    }

    for(i = 0; i < limit; i++) {
        printf("longest matching sid: index %i lmatch index: %i\n", i, longest_matching_sid[i]);
    }

    return limit;
}

#if defined(ENABLE_NOT_USED)
static void randomize_service_ids() {
    bzero(services, sizeof(struct service_id) * MAX_SERVICE_ID);
    int i = 0;
    for(i = 0; i < MAX_SERVICE_ID; i++) {
        longest_matching_sid[i] = -1;
    }

    int j = 0;
    for(i = 0; i < MAX_SERVICE_ID; i++) {
        initialize_service_id(&services[i].sv_srvid, 0);
        services[i].sv_prefix_bits = (uint8_t) (rand() / (float) RAND_MAX * MAX_SERVICE_ID);

        //        printf("service id %i prefix %u, sid %s\n", i, services[i].sv_prefix_bits,
        //                service_id_to_str(&services[i].sv_srvid));

    }

    int longest = 0;

    for(i = 0; i < MAX_SERVICE_ID; i++) {
        for(j = i + 1; j < MAX_SERVICE_ID; j++) {
            longest = find_longest_common_prefix(services[i].sv_srvid.srv_un.un_id8,
                    services[j].sv_srvid.srv_un.un_id8, 0, services[i].sv_prefix_bits);

            if(longest >= services[j].sv_prefix_bits && services[j].sv_prefix_bits
                    > services[longest_matching_sid[i]].sv_prefix_bits) {
                longest_matching_sid[i] = j;
            }
        }
    }

}
#endif /* ENABLE_NOT_USED */

static void initialize_service_ids() {
    bzero(services, sizeof(struct service_id) * MAX_SERVICE_ID);
    int i = 0;
    for(i = 0; i < MAX_SERVICE_ID; i++) {
        longest_matching_sid[i] = -1;
    }

    int j = 0;
    for(i = 0; i < MAX_SERVICE_ID; i += 8) {

        initialize_service_id(&services[i].sv_srvid, 0);
        /*full length*/
        services[i].sv_prefix_bits = 255;

        printf("service id %i prefix %u, sid %s\n", i, services[i].sv_prefix_bits,
                service_id_to_str(&services[i].sv_srvid));

        for(j = 1; j < 8; j++) {
            /*copy the first over into the rest the randomize the bits post prefix*/
            memcpy(&services[i + j].sv_srvid, &services[i].sv_srvid, sizeof(struct service_id));
            services[i + j].sv_prefix_bits = (j * 32 + (int) (((float) rand() / RAND_MAX) * 32))
                    % 248;

            if(services[i + j].sv_prefix_bits < 32) {
                /* bit overflow
                 */
                services[i + j].sv_prefix_bits = 248;
                services[i + j].sv_srvid.srv_un.un_id8[31]
                        = ~services[i].sv_srvid.srv_un.un_id8[31];
            } else {
                initialize_service_id(&services[i + j].sv_srvid, services[i + j].sv_prefix_bits);
            }

        }
    }

    int longest = 0;

    for(i = 0; i < MAX_SERVICE_ID; i++) {
        for(j = i + 1; j < MAX_SERVICE_ID; j++) {
            longest = find_longest_common_prefix(services[i].sv_srvid.srv_un.un_id8,
                    services[j].sv_srvid.srv_un.un_id8, 0, services[i].sv_prefix_bits);

            if(longest >= services[j].sv_prefix_bits && services[j].sv_prefix_bits
                    > services[longest_matching_sid[i]].sv_prefix_bits) {
                longest_matching_sid[i] = j;
            }
        }
    }

    for(i = 0; i < MAX_SERVICE_ID; i++) {
        printf("longest matching sid: index %i lmatch index: %i\n", i, longest_matching_sid[i]);
    }

}

static void reverse_service_ids() {

    int i = 0;
    for(i = 0; i < MAX_SERVICE_ID; i++) {
        longest_matching_sid[i] = -1;
    }

    /*service id's must be initialized*/
    struct sockaddr_sv service;

    for(i = 0; i < 128; i++) {
        memcpy(&service, &services[MAX_SERVICE_ID - i - 1], sizeof(service));
        memcpy(&services[MAX_SERVICE_ID - i - 1], &services[i], sizeof(service));
        memcpy(&services[i], &service, sizeof(service));
    }

    int longest = 0;

    int j = 0;
    for(i = 0; i < MAX_SERVICE_ID; i++) {
        for(j = i + 1; j < MAX_SERVICE_ID; j++) {
            longest = find_longest_common_prefix(services[i].sv_srvid.srv_un.un_id8,
                    services[j].sv_srvid.srv_un.un_id8, 0, services[i].sv_prefix_bits);

            if(longest >= services[j].sv_prefix_bits && services[j].sv_prefix_bits
                    > services[longest_matching_sid[i]].sv_prefix_bits) {
                longest_matching_sid[i] = j;
            }
        }
    }
}

static int find_unique_service(struct sockaddr_sv* service, int* matched) {
    int i = 0;
    for(i = 0; i < MAX_SERVICE_ID; i++) {
        assert(matched[i] < 2);
        if(services[i].sv_prefix_bits == service->sv_prefix_bits && memcmp(
                services[i].sv_srvid.srv_un.un_id8, service->sv_srvid.srv_un.un_id8, 32) == 0) {

            if(matched[i] == 0) {
                matched[i]++;
                return TRUE;
            }
            return FALSE;
        }
    }
    return FALSE;
}

static int find_longest_prefix_match(struct sockaddr_sv* service, int offset, int limit) {
    int longest = -1;
    int max = -1;
    int common = 0;
    int i = 0;
    for(i = offset; i < limit; i++) {
        if(services[i].sv_prefix_bits <= service->sv_prefix_bits) {
            common = find_longest_common_prefix(service->sv_srvid.srv_un.un_id8,
                    services[i].sv_srvid.srv_un.un_id8, 0, service->sv_prefix_bits);

            //if(common >= services[i].sv_prefix_bits && common > max) {
            //max = common;
            if(common >= services[i].sv_prefix_bits && services[i].sv_prefix_bits > max) {
                max = services[i].sv_prefix_bits;
                longest = i;
            }
        }
    }

    return longest;

}

static void test_prefix_trie() {
    int matched[MAX_SERVICE_ID];
    bzero(matched, MAX_SERVICE_ID * sizeof(int));

    /*create the set of service id's*/
    /*blocks of 8 - 1 random bit string prefix 1-32 from 7-8*/

    struct prefix_trie_struct trie;
    bzero(&trie, sizeof(trie));
    prefix_trie_initialize(&trie, MAX_SERVICE_ID, 0.5);

    /*insert into the trie and query*/
    int i = 0;
    int j = 0;
    int count = 0;
    for(; i < MAX_SERVICE_ID; i += 8) {

        /* no default and no key yet*/
        assert(prefix_trie_find(&trie, services[i].sv_srvid.srv_un.un_id8, 0) == NULL);
        assert(prefix_trie_find(&trie, services[i].sv_srvid.srv_un.un_id8, 255) == NULL);
        assert(prefix_trie_find_exact(&trie, services[i].sv_srvid.srv_un.un_id8, 0) == NULL);
        assert(prefix_trie_find_exact(&trie, services[i].sv_srvid.srv_un.un_id8, 255) == NULL);
        assert(prefix_trie_has_key(&trie, services[i].sv_srvid.srv_un.un_id8, 0) == FALSE);
        assert(prefix_trie_has_key(&trie, services[i].sv_srvid.srv_un.un_id8, 255) == FALSE);

        /*test insert - no replace*/
        assert(prefix_trie_insert(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits, &services[i]) == NULL);

        //print_trie(&trie);
        count++;
        assert(prefix_trie_count(&trie) == count);

        /*test replace*/
        assert(prefix_trie_insert(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits, &services[i]) == &services[i]);

        assert(prefix_trie_count(&trie) == count);

        /*test basic find exact and has key*/
        assert(prefix_trie_find_exact(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits) == &services[i]);
        assert(prefix_trie_has_key(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits));

        /* test all prefix lengths from the prefix length up to the max length*/
        for(j = services[i].sv_prefix_bits; j < 256; j++) {
            assert(prefix_trie_find(&trie, services[i].sv_srvid.srv_un.un_id8, j) == &services[i]);
        }

        /* insert the remaining services in the block - they should all be prefixes of the original*/
        for(j = 1; j < 8; j++) {
            assert(prefix_trie_insert(&trie, services[i + j].sv_srvid.srv_un.un_id8,
                    services[i + j].sv_prefix_bits, &services[i + j]) == NULL);
            count++;
            assert(prefix_trie_count(&trie) == count);

            /*exact matches*/
            assert(prefix_trie_find_exact(&trie, services[i + j].sv_srvid.srv_un.un_id8, services[i
                    + j].sv_prefix_bits) == &services[i + j]);
            assert(prefix_trie_has_key(&trie, services[i + j].sv_srvid.srv_un.un_id8, services[i
                    + j].sv_prefix_bits));

            /*longest prefix match*/
            assert(prefix_trie_find(&trie, services[i + j].sv_srvid.srv_un.un_id8,
                    (services[i + j].sv_prefix_bits + 4 >= 255 ? services[i + j].sv_prefix_bits
                            : services[i + j].sv_prefix_bits + 4)) == &services[i + j]);

            assert(prefix_trie_find_exact(&trie, services[i + j].sv_srvid.srv_un.un_id8, services[i
                    + j].sv_prefix_bits + 1) == NULL);
            assert(prefix_trie_has_key(&trie, services[i + j].sv_srvid.srv_un.un_id8, services[i
                    + j].sv_prefix_bits + 1) == FALSE);

        }

        /*the original should still match itself*/
        assert(prefix_trie_find(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits) == &services[i]);

        assert(prefix_trie_find_exact(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits) == &services[i]);
        assert(prefix_trie_has_key(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits));

    }

    /*iteration check*/
    struct prefix_trie_iter iter;
    bzero(&iter, sizeof(iter));
    prefix_trie_iter_init(&iter, &trie);

    print_trie(&trie);

    uint8_t* key;
    uint16_t prefix;
    int longest = -1;
    struct sockaddr_sv* service;

    i = 0;

    while(prefix_trie_iter_next(&iter, &key, &prefix, (void**) &service)) {
        i++;
        printf("iter check: %i %s\n", prefix, service_id_to_str(&service->sv_srvid));
        assert(find_unique_service(service, matched));
    }

    assert(i == prefix_trie_count(&trie));
    assert(i == MAX_SERVICE_ID);
    prefix_trie_iter_destroy(&iter);

    printf("before remove\n");
    print_trie(&trie);

    /*removal check*/
    for(i = 0; i < MAX_SERVICE_ID - 1; i++) {
        assert(prefix_trie_find(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits) == &services[i]);
        assert(prefix_trie_find_exact(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits) == &services[i]);
        assert(prefix_trie_has_key(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits));

        assert(prefix_trie_remove(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits) == &services[i]);
        count--;
        assert(prefix_trie_count(&trie) == count);

        assert(prefix_trie_find_exact(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits) == NULL);
        assert(prefix_trie_has_key(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits) == FALSE);

        if(longest_matching_sid[i] >= 0) {
            service = prefix_trie_find(&trie, services[i].sv_srvid.srv_un.un_id8,
                    services[i].sv_prefix_bits);
            if(service != &services[longest_matching_sid[i]]) {

                printf("longest matching mismatch: index %i lmatch index: %i found %s lmatch %s\n",
                        i, longest_matching_sid[i], service_id_to_str(&service->sv_srvid),
                        service_id_to_str(&services[longest_matching_sid[i]].sv_srvid));
            }

            assert(service == &services[longest_matching_sid[i]]);
        }

        //print_trie(&trie);

        for(j = 0; j < MAX_SERVICE_ID; j++) {
            longest = find_longest_prefix_match(&services[j], i + 1, MAX_SERVICE_ID);
            if(longest >= 0) {
                service = prefix_trie_find(&trie, services[j].sv_srvid.srv_un.un_id8,
                        services[j].sv_prefix_bits);
                if(service != &services[longest]) {

                    printf("longest prefix mismatch: offset: %i, longest %i prefix %u sid %s\n", i
                            + 1, longest, services[longest].sv_prefix_bits, service_id_to_str(
                            &services[longest].sv_srvid));
                }
                assert(service == &services[longest]);
            }
        }
    }

    assert(prefix_trie_count(&trie) == 1);
    assert(prefix_trie_remove(&trie, services[MAX_SERVICE_ID - 1].sv_srvid.srv_un.un_id8,
            services[i].sv_prefix_bits) == &services[MAX_SERVICE_ID - 1]);
    count--;
    assert(prefix_trie_count(&trie) == count);

    /*test a default value */
    prefix_trie_insert(&trie, services[0].sv_srvid.srv_un.un_id8, 0, &services[0]);

    for(i = 0; i < MAX_SERVICE_ID; i++) {
        assert(prefix_trie_find(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits) == &services[0]);
    }

    struct sockaddr_sv serv;
    bzero(&serv, sizeof(serv));
    memcpy(&serv, &services[8], sizeof(serv));
    serv.sv_srvid.srv_un.un_id8[0] = ~serv.sv_srvid.srv_un.un_id8[0];

    /*test default with values*/
    prefix_trie_insert(&trie, services[8].sv_srvid.srv_un.un_id8, 255, &services[8]);

    assert(prefix_trie_find(&trie, serv.sv_srvid.srv_un.un_id8, serv.sv_prefix_bits)
            == &services[0]);

    assert(prefix_trie_remove(&trie, services[0].sv_srvid.srv_un.un_id8, 0) == &services[0]);
    assert(prefix_trie_remove(&trie, services[8].sv_srvid.srv_un.un_id8, 255) == &services[8]);
    assert(prefix_trie_count(&trie) == 0);

    for(i = 0; i < MAX_SERVICE_ID; i++) {
        assert(prefix_trie_find(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits) == NULL);
    }

    printf("before inserting\n");
    print_trie(&trie);

    /* insert and test iter remove*/
    for(i = 0; i < MAX_SERVICE_ID; i++) {
        matched[i] = 0;
    }
    count = 0;

    for(i = 0; i < MAX_SERVICE_ID; i++) {
        /* no default */
        assert(prefix_trie_insert(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits, &services[i]) == NULL);

        count++;
        assert(prefix_trie_count(&trie) == count);
    }

    printf("after insert before iter remove\n");
    print_trie(&trie);

    /*iter remove*/

    bzero(&iter, sizeof(iter));
    prefix_trie_iter_init(&iter, &trie);

    longest = -1;
    i = 0;

    while(prefix_trie_iter_next(&iter, &key, &prefix, (void**) &service)) {
        i++;
        assert(prefix_trie_find(&trie, key, prefix) == service);
        assert(find_unique_service(service, matched));
        printf("next service: %u %s\n", service->sv_prefix_bits, service_id_to_str(
                &service->sv_srvid));
        prefix_trie_iter_remove(&iter);

        assert(prefix_trie_count(&trie) == MAX_SERVICE_ID - i);
        assert(prefix_trie_find(&trie, key, prefix) != service);

        //print_trie(&trie);
    }

    printf("total iter/remove iterations: %u\n", i);
    assert(0 == prefix_trie_count(&trie));
    assert(i == MAX_SERVICE_ID);
    prefix_trie_iter_destroy(&iter);

    print_trie(&trie);
    prefix_trie_finalize(&trie);

}

static void test_spec_prefix_trie(int limit) {
    int matched[MAX_SERVICE_ID];
    bzero(matched, MAX_SERVICE_ID * sizeof(int));

    /*create the set of service id's*/
    /*blocks of 8 - 1 random bit string prefix 1-32 from 7-8*/

    struct prefix_trie_struct trie;
    bzero(&trie, sizeof(trie));
    prefix_trie_initialize(&trie, MAX_SERVICE_ID, 0.5);

    /*insert into the trie and query*/
    int i = 0;
    int j = 0;
    int count = 0;

    struct sockaddr_sv serv;
    struct sockaddr_sv* service = NULL;

    uint8_t byteval = 0;
    uint8_t rem = 0;
    uint8_t bindex = 0;

    uint8_t* key;
    uint16_t prefix;
    int longest = -1;

    for(; i < limit; i++) {

        /* no default and no key yet*/
        assert(prefix_trie_find(&trie, services[i].sv_srvid.srv_un.un_id8, 0) == NULL);
        //        assert(prefix_trie_find(&trie, services[i].sv_srvid.srv_un.un_id8,
        //                services[i].sv_prefix_bits) == NULL);
        assert(prefix_trie_find_exact(&trie, services[i].sv_srvid.srv_un.un_id8, 0) == NULL);
        assert(prefix_trie_find_exact(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits) == NULL);
        assert(prefix_trie_has_key(&trie, services[i].sv_srvid.srv_un.un_id8, 0) == FALSE);
        assert(prefix_trie_has_key(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits) == FALSE);

        /*test insert - no replace*/
        assert(prefix_trie_insert(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits, &services[i]) == NULL);

        //print_trie(&trie);
        count++;
        assert(prefix_trie_count(&trie) == count);

        /*lpm find*/
        assert(prefix_trie_find(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits) == &services[i]);

        memcpy(&serv, &services[i], sizeof(serv));
        /*test lpm find with varied keys with the same prefix*/

        bindex = serv.sv_prefix_bits / 8;
        rem = serv.sv_prefix_bits % 8;
        byteval = serv.sv_srvid.srv_un.un_id8[bindex];

        if(rem == 0) {
            byteval = ~serv.sv_srvid.srv_un.un_id8[++bindex];
        } else {
            byteval = (byteval & 0xFF << (8 - rem)) | (~(byteval & 0xFF >> rem) & 0xFF >> rem);
        }

        serv.sv_srvid.srv_un.un_id8[bindex] = byteval;

        service = prefix_trie_find(&trie, serv.sv_srvid.srv_un.un_id8, serv.sv_prefix_bits);

        if(service != NULL) {
            printf("LPM find: prefix: %u %s\n", service->sv_prefix_bits, service_id_to_str(
                    &service->sv_srvid));
        }
        assert(service == &services[i]);

        /*test lpm find with varied keys with a longer prefix*/
        serv.sv_prefix_bits += 10;
        longest = find_longest_prefix_match(&services[j], 0, limit);
        if(longest >= 0) {
            service = prefix_trie_find(&trie, services[j].sv_srvid.srv_un.un_id8,
                    services[j].sv_prefix_bits);
            if(service != &services[longest]) {

                printf("longest prefix mismatch: offset: %i, longest %i prefix %u sid %s\n", i + 1,
                        longest, services[longest].sv_prefix_bits, service_id_to_str(
                                &services[longest].sv_srvid));
            }
            assert(service == &services[longest]);
        }

        assert(prefix_trie_find_exact(&trie, serv.sv_srvid.srv_un.un_id8, serv.sv_prefix_bits)
                == NULL);

        assert(prefix_trie_has_key(&trie, serv.sv_srvid.srv_un.un_id8, serv.sv_prefix_bits)
                == FALSE);

        /*test replace*/
        assert(prefix_trie_insert(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits, &services[i]) == &services[i]);

        assert(prefix_trie_count(&trie) == count);

        /*test basic find exact and has key*/
        assert(prefix_trie_find_exact(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits) == &services[i]);
        assert(prefix_trie_has_key(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits));
    }

    /*iteration check*/
    struct prefix_trie_iter iter;
    bzero(&iter, sizeof(iter));
    prefix_trie_iter_init(&iter, &trie);

    print_trie(&trie);

    i = 0;

    while(prefix_trie_iter_next(&iter, &key, &prefix, (void**) &service)) {
        i++;
        printf("iter check: %i %s\n", prefix, service_id_to_str(&service->sv_srvid));
        /*won't work with the replica inserts - need to know how many*/
        //assert(find_unique_service(service, matched));
    }

    assert(i == prefix_trie_count(&trie));
    assert(i == limit);
    prefix_trie_iter_destroy(&iter);

    printf("before remove\n");
    print_trie(&trie);

    /*removal check*/
    for(i = 0; i < limit; i++) {
        assert(prefix_trie_find(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits) == &services[i]);
        assert(prefix_trie_find_exact(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits) == &services[i]);
        assert(prefix_trie_has_key(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits));

        assert(prefix_trie_remove(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits) == &services[i]);
        count--;
        assert(prefix_trie_count(&trie) == count);

        assert(prefix_trie_find_exact(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits) == NULL);
        assert(prefix_trie_has_key(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits) == FALSE);

        if(longest_matching_sid[i] >= 0) {
            service = prefix_trie_find(&trie, services[i].sv_srvid.srv_un.un_id8,
                    services[i].sv_prefix_bits);
            if(service != &services[longest_matching_sid[i]]) {

                printf(
                        "longest matching mismatch: index %i lmatch index: %i fprefix: %u lprefix: %u found %s lmatch %s\n",
                        i, longest_matching_sid[i], service->sv_prefix_bits,
                        services[longest_matching_sid[i]].sv_prefix_bits, service_id_to_str(
                                &service->sv_srvid), service_id_to_str(
                                &services[longest_matching_sid[i]].sv_srvid));
            }

            assert(service == &services[longest_matching_sid[i]]);
        }

        //print_trie(&trie);

        for(j = 0; j < limit; j++) {
            longest = find_longest_prefix_match(&services[j], i + 1, limit);
            if(longest >= 0) {
                service = prefix_trie_find(&trie, services[j].sv_srvid.srv_un.un_id8,
                        services[j].sv_prefix_bits);
                if(service != &services[longest]) {

                    printf("longest prefix mismatch: offset: %i, longest %i prefix %u sid %s\n", i
                            + 1, longest, services[longest].sv_prefix_bits, service_id_to_str(
                            &services[longest].sv_srvid));
                }
                assert(service == &services[longest]);
            }
        }
    }

    assert(prefix_trie_count(&trie) == 0);

    /*test a default value */
    prefix_trie_insert(&trie, services[0].sv_srvid.srv_un.un_id8, 0, &services[0]);

    for(i = 0; i < limit; i++) {
        assert(prefix_trie_find(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits) == &services[0]);
    }

    bzero(&serv, sizeof(serv));
    memcpy(&serv, &services[8], sizeof(serv));
    serv.sv_srvid.srv_un.un_id8[0] = ~serv.sv_srvid.srv_un.un_id8[0];

    /*test default with values*/
    prefix_trie_insert(&trie, services[8].sv_srvid.srv_un.un_id8, 255, &services[8]);

    assert(prefix_trie_find(&trie, serv.sv_srvid.srv_un.un_id8, serv.sv_prefix_bits)
            == &services[0]);

    assert(prefix_trie_remove(&trie, services[0].sv_srvid.srv_un.un_id8, 0) == &services[0]);
    assert(prefix_trie_remove(&trie, services[8].sv_srvid.srv_un.un_id8, 255) == &services[8]);
    assert(prefix_trie_count(&trie) == 0);

    for(i = 0; i < MAX_SERVICE_ID; i++) {
        assert(prefix_trie_find(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits) == NULL);
    }

    printf("before inserting\n");
    print_trie(&trie);

    /* insert and test iter remove*/
    for(i = 0; i < MAX_SERVICE_ID; i++) {
        matched[i] = 0;
    }
    count = 0;

    for(i = 0; i < limit; i++) {
        /* no default */
        assert(prefix_trie_insert(&trie, services[i].sv_srvid.srv_un.un_id8,
                services[i].sv_prefix_bits, &services[i]) == NULL);

        count++;
        assert(prefix_trie_count(&trie) == count);
    }

    printf("after insert before iter remove\n");
    print_trie(&trie);

    /*iter remove*/

    bzero(&iter, sizeof(iter));
    prefix_trie_iter_init(&iter, &trie);

    longest = -1;
    i = 0;

    while(prefix_trie_iter_next(&iter, &key, &prefix, (void**) &service)) {
        i++;
        assert(prefix_trie_find(&trie, key, prefix) == service);
        assert(find_unique_service(service, matched));
        printf("next service: %u %s\n", service->sv_prefix_bits, service_id_to_str(
                &service->sv_srvid));
        prefix_trie_iter_remove(&iter);

        assert(prefix_trie_count(&trie) == limit - i);
        assert(prefix_trie_find(&trie, key, prefix) != service);

        //print_trie(&trie);
    }

    printf("total iter/remove iterations: %u\n", i);
    assert(0 == prefix_trie_count(&trie));
    assert(i == limit);
    prefix_trie_iter_destroy(&iter);

    print_trie(&trie);
    prefix_trie_finalize(&trie);
}

int main(int argc, char **argv) {

    srand(10012314);

    initialize_service_ids();
    test_prefix_trie();

    reverse_service_ids();
    test_prefix_trie();

    int limit = spec_service_ids();
    test_spec_prefix_trie(limit);
    return 0;
}
