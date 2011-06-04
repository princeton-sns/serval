/*
 * service_table_test.c
 *
 *  Created on: Mar 9, 2011
 *      Author: daveds
 */

/*
 *
 * */
#include "service_table.h"
#include "prefixtrie.h"
#include "service_util.h"
#include "service_types.h"
#include <sys/time.h>

#define UNIQUE_SERVICE_IDS 5096
#define SERVICE_REPLICATION_FACTOR 4
#define UNIQUE_SERVICE_REFERENCES UNIQUE_SERVICE_IDS * SERVICE_REPLICATION_FACTOR

static struct sockaddr_sv services[UNIQUE_SERVICE_IDS];
static int longest_matching_sid[UNIQUE_SERVICE_IDS];

static struct service_reference references[UNIQUE_SERVICE_REFERENCES];

/*TODO - test resolution distribution */

static int find_unique_service_reference(struct service_reference* ref, int* matched) {
    int i = 0;
    for(i = 0; i < UNIQUE_SERVICE_REFERENCES; i++) {
        assert(matched[i] < 2);
        if(references[i].instance.service.sv_prefix_bits == ref->instance.service.sv_prefix_bits
                && memcmp(references[i].instance.service.sv_srvid.srv_un.un_id8,
                        ref->instance.service.sv_srvid.srv_un.un_id8, 32) == 0 && memcmp(
                &references[i].instance.address, &ref->instance.address,
                sizeof(ref->instance.address)) == 0) {

            if(matched[i] == 0) {
                matched[i]++;
                return TRUE;
            }
            printf("More than 1 match (%i) for service: %s addr1: %i addr2: %i\n", matched[i],
                    service_id_to_str(&ref->instance.service.sv_srvid),
                    ref->instance.address.sin.sin_addr.s_addr,
                    references[i].instance.address.sin.sin_addr.s_addr);
            return FALSE;
        }
    }
    printf("Could not find unique service: %s\n",
            service_id_to_str(&ref->instance.service.sv_srvid));
    return FALSE;
}

static void initialize_service_references() {
    bzero(services, sizeof(struct service_id) * UNIQUE_SERVICE_IDS);
    bzero(references, sizeof(struct service_reference) * UNIQUE_SERVICE_REFERENCES);
    int i = 0;
    for(i = 0; i < UNIQUE_SERVICE_IDS; i++) {
        longest_matching_sid[i] = -1;
    }

    struct service_reference* ref;
    int j = 0;
    int pridiv = SERVICE_REPLICATION_FACTOR >> 1 == 0 ? 1 : SERVICE_REPLICATION_FACTOR >> 1;

    for(i = 0; i < UNIQUE_SERVICE_IDS; i++) {
        initialize_service_id(&services[i].sv_srvid, 0);
        //services[i].sv_prefix_bits = (int) (((float) rand() / RAND_MAX) * 255);
        //services[i].sv_prefix_bits = 128 + (int) (((float) rand() / RAND_MAX) * 127);
        services[i].sv_prefix_bits = 255;

        printf("service id %i prefix %u, sid %s\n", i, services[i].sv_prefix_bits,
                service_id_to_str(&services[i].sv_srvid));

        for(j = 0; j < SERVICE_REPLICATION_FACTOR; j++) {
            /*copy the first over into the rest the randomize the bits post prefix*/
            ref = references + (i * SERVICE_REPLICATION_FACTOR + j);
            memcpy(&ref->instance.service.sv_srvid, &services[i].sv_srvid,
                    sizeof(struct service_id));
            ref->instance.service.sv_prefix_bits = services[i].sv_prefix_bits;
            /*random network address*/
            ref->instance.address.sin.sin_addr.s_addr = (int) rand();

            ref->capacity = i % 20;
            ref->hard_timeout = 300 + i % 128;
            ref->idle_timeout = 10 + i % 64;
            ref->priority = 2048 + i / pridiv;
            ref->weight = 1024 + i;
            ref->ttl = 256 + (i + j % 32);
            ref->tokens_consumed = 128 + j;
            ref->registered = 96 + (i << 3) - j;
        }
    }

    int longest = 0;

    for(i = 0; i < UNIQUE_SERVICE_IDS; i++) {
        for(j = i + 1; j < UNIQUE_SERVICE_IDS; j++) {
            longest = find_longest_common_prefix(services[i].sv_srvid.srv_un.un_id8,
                    services[j].sv_srvid.srv_un.un_id8, 0, services[i].sv_prefix_bits);

            if(longest >= services[j].sv_prefix_bits && services[j].sv_prefix_bits
                    > services[longest_matching_sid[i]].sv_prefix_bits) {
                longest_matching_sid[i] = j;
            }
        }
    }

    for(i = 0; i < UNIQUE_SERVICE_IDS; i++) {
        printf("longest matching sid: index %i lmatch index: %i\n", i, longest_matching_sid[i]);
    }

}

static void test_service_table() {
    int matched[UNIQUE_SERVICE_REFERENCES];
    bzero(matched, UNIQUE_SERVICE_REFERENCES * sizeof(int));

    /*create the set of service references */
    /*8 replicas per 256 random serviceID's*/

    struct sv_service_table table;

    bzero(&table, sizeof(table));

    assert(service_table_initialize(&table) == 0);

    struct service_reference* ref;
    struct service_reference* sref;
    struct service_reference** refs;

    /*insert into the trie and query*/
    int i = 0;
    int j = 0;
    int k = 0;
    size_t count = 0;
    int total_count = 0;
    int longest = -1;

    for(; i < UNIQUE_SERVICE_REFERENCES; i++) {
        ref = &references[i];
        //        printf("Inserting service reference: %s @ %i\n", service_id_to_str(
        //                &ref->instance.service.sv_srvid), ref->instance.address.sin.sin_addr.s_addr);
        j = i % SERVICE_REPLICATION_FACTOR;
        /* no default and no key yet*/
        assert(service_table_find_service_reference(&table, ref->instance.service.sv_flags,
                ref->instance.service.sv_prefix_bits, &ref->instance.service.sv_srvid,
                (struct net_addr*) &ref->instance.address.sin.sin_addr) == NULL);

        assert(service_table_find_service_references(&table, ref->instance.service.sv_flags,
                ref->instance.service.sv_prefix_bits, &ref->instance.service.sv_srvid, &refs,
                &count) == 0);

        //printf("Found: %i references j=%i\n", count, j);
        assert(j == count);

        if(j > 0) {
            assert(refs);
            for(k = 0; k < count; k++) {
                sref = refs[k];
                assert(memcmp(&ref->instance.service.sv_srvid, &sref->instance.service.sv_srvid,
                        sizeof(struct service_id)) == 0);
                assert(ref->instance.service.sv_prefix_bits
                        == sref->instance.service.sv_prefix_bits);
            }
            free(refs);
        }

        sref = service_table_resolve_service(&table, ref->instance.service.sv_flags,
                ref->instance.service.sv_prefix_bits, &ref->instance.service.sv_srvid);

        if(count > 0) {
            assert(sref);
            assert(memcmp(&ref->instance.service.sv_srvid, &sref->instance.service.sv_srvid,
                    sizeof(struct service_id)) == 0);
            assert(ref->instance.service.sv_prefix_bits == sref->instance.service.sv_prefix_bits);
        } else {
            assert(sref == NULL);
        }

        /*test insert - no replace*/
        //5c45 - missing
        //5c4e - sibling
        //5c56 - replace
        if(ref->instance.service.sv_srvid.srv_un.un_id8[0] == 0xb7
                && (ref->instance.service.sv_srvid.srv_un.un_id8[1] & 0xF0) == 0xb0) {
            printf("Adding in the trouble makers: %s\n", service_id_to_str(
                    &ref->instance.service.sv_srvid));
            longest += count;
            assert(longest >= -1);
        }

        assert(service_table_add_service_reference(&table, ref) > 0);

        //print_trie(&trie);

        total_count++;
        assert(service_table_size(&table) == total_count);

        /*should not work*/
        assert(service_table_add_service_reference(&table, ref) == -1);
        /*test replace*/
        assert(service_table_size(&table) == total_count);

        assert(service_table_find_service_reference(&table, ref->instance.service.sv_flags,
                ref->instance.service.sv_prefix_bits, &ref->instance.service.sv_srvid,
                (struct net_addr*) &ref->instance.address.sin.sin_addr) == ref);

        assert(service_table_find_service_references(&table, ref->instance.service.sv_flags,
                ref->instance.service.sv_prefix_bits, &ref->instance.service.sv_srvid, &refs,
                &count) == 0);

        assert(j + 1 == count);
        assert(refs);
        for(k = 0; k < count; k++) {
            sref = refs[k];
            assert(memcmp(&ref->instance.service.sv_srvid, &sref->instance.service.sv_srvid,
                    sizeof(struct service_id)) == 0);
            assert(ref->instance.service.sv_prefix_bits == sref->instance.service.sv_prefix_bits);
        }
        free(refs);

        sref = service_table_resolve_service(&table, ref->instance.service.sv_flags,
                ref->instance.service.sv_prefix_bits, &ref->instance.service.sv_srvid);

        assert(sref);
        assert(memcmp(&ref->instance.service.sv_srvid, &sref->instance.service.sv_srvid,
                sizeof(struct service_id)) == 0);
        assert(ref->instance.service.sv_prefix_bits == sref->instance.service.sv_prefix_bits);

    }
    assert(total_count == service_table_size(&table) && total_count == UNIQUE_SERVICE_REFERENCES);
    /*iteration check*/
    struct service_table_iter iter;
    bzero(&iter, sizeof(iter));
    service_table_iter_init(&iter, &table);

    //print_trie(&trie);

    //uint8_t* key;
    //uint16_t prefix;
    //struct sockaddr_sv* service;

    i = 0;
    struct timeval ntime;
    bzero(&ntime, sizeof(ntime));
    gettimeofday(&ntime, NULL);
    long long ctime = ntime.tv_sec * 1000000LL + ntime.tv_usec;
    while(service_table_iter_next(&iter, &sref)) {
        assert(sref);
        i++;
        //        printf("iter check: i %i ref count %i prefix bits %i service id %s address: %i\n", i,
        //                service_table_iter_reference_count(&iter), sref->instance.service.sv_prefix_bits,
        //                service_id_to_str(&sref->instance.service.sv_srvid),
        //                sref->instance.address.sin.sin_addr.s_addr);
        assert(find_unique_service_reference(sref, matched));
        assert(service_table_iter_reference_count(&iter) == SERVICE_REPLICATION_FACTOR);
    }

    bzero(&ntime, sizeof(ntime));
    gettimeofday(&ntime, NULL);

    printf("elapsed iter time: %lli\n", ntime.tv_sec* 1000000LL + ntime.tv_usec - ctime);

    if(i != service_table_size(&table)) {
        for(j = 0; j < UNIQUE_SERVICE_REFERENCES; j++) {
            if(matched[j] == 0) {
                printf("Iter check missed service ref: %s @ %i\n", service_id_to_str(
                        &references[j].instance.service.sv_srvid),
                        references[j].instance.address.sin.sin_addr.s_addr);
            }
        }

        print_trie(&table.service_trie);
    }

    printf("total iterations: %i table size: %zu unique refs: %i\n", i, service_table_size(&table),
            UNIQUE_SERVICE_REFERENCES);

    assert(i == service_table_size(&table));
    assert(i == UNIQUE_SERVICE_REFERENCES);
    service_table_iter_destroy(&iter);

    printf("before remove\n");
    //print_trie(&trie);

    /*removal check*/
    for(i = 0; i < UNIQUE_SERVICE_REFERENCES; i++) {
        ref = &references[i];
        j = SERVICE_REPLICATION_FACTOR - (i % SERVICE_REPLICATION_FACTOR);
        /* no default and no key yet*/
        //        printf("Removing service reference: %s @ %i\n", service_id_to_str(
        //                &ref->instance.service.sv_srvid), ref->instance.address.sin.sin_addr.s_addr);

        assert(service_table_find_service_reference(&table, ref->instance.service.sv_flags,
                ref->instance.service.sv_prefix_bits, &ref->instance.service.sv_srvid,
                (struct net_addr*) &ref->instance.address.sin.sin_addr) == ref);

        assert(service_table_find_service_references(&table, ref->instance.service.sv_flags,
                ref->instance.service.sv_prefix_bits, &ref->instance.service.sv_srvid, &refs,
                &count) == 0);

        assert(j == count);
        if(j > 0) {
            assert(refs);
            for(k = 0; k < count; k++) {
                sref = refs[k];
                assert(memcmp(&ref->instance.service.sv_srvid, &sref->instance.service.sv_srvid,
                        sizeof(struct service_id)) == 0);
                assert(ref->instance.service.sv_prefix_bits
                        == sref->instance.service.sv_prefix_bits);
            }
            free(refs);
        }

        if(count == 1 && (ref->instance.service.sv_srvid.srv_un.un_id8[0] & 0xF0) == 0xb0) {
            //&& (ref->instance.service.sv_srvid.srv_un.un_id8[1] & 0xF0) == 0xa0) {
            printf("Removing trouble makers: %s\n", service_id_to_str(
                    &ref->instance.service.sv_srvid));
            longest += count;
            assert(longest >= -1);
        }

        assert(service_table_remove_service_reference(&table, ref->instance.service.sv_flags,
                ref->instance.service.sv_prefix_bits, &ref->instance.service.sv_srvid,
                (struct net_addr*) &ref->instance.address.sin.sin_addr, &sref) >= 0);
        assert(sref == ref);
        total_count--;
        assert(service_table_size(&table) == total_count);

        assert(service_table_find_service_reference(&table, ref->instance.service.sv_flags,
                ref->instance.service.sv_prefix_bits, &ref->instance.service.sv_srvid,
                (struct net_addr*) &ref->instance.address.sin.sin_addr) == NULL);

        assert(service_table_find_service_references(&table, ref->instance.service.sv_flags,
                ref->instance.service.sv_prefix_bits, &ref->instance.service.sv_srvid, &refs,
                &count) == 0);

        assert(j - 1 == count);
        if(j - 1 > 0) {
            assert(refs);
            for(k = 0; k < count; k++) {
                sref = refs[k];
                assert(memcmp(&ref->instance.service.sv_srvid, &sref->instance.service.sv_srvid,
                        sizeof(struct service_id)) == 0);
                assert(ref->instance.service.sv_prefix_bits
                        == sref->instance.service.sv_prefix_bits);
            }
            free(refs);
        }

        sref = service_table_resolve_service(&table, ref->instance.service.sv_flags,
                ref->instance.service.sv_prefix_bits, &ref->instance.service.sv_srvid);

        if(j - 1 > 0) {
            assert(sref);
            assert(memcmp(&ref->instance.service.sv_srvid, &sref->instance.service.sv_srvid,
                    sizeof(struct service_id)) == 0);
            assert(ref->instance.service.sv_prefix_bits == sref->instance.service.sv_prefix_bits);
        } else if(longest_matching_sid[i / SERVICE_REPLICATION_FACTOR] >= 0) {
            assert(sref);
            //                    if(service != &services[longest_matching_sid[i]]) {
            //
            //                                    printf("longest matching mismatch: index %i lmatch index: %i found %s lmatch %s\n",
            //                                            i, longest_matching_sid[i], service_id_to_str(&service->sv_srvid),
            //                                            service_id_to_str(&services[longest_matching_sid[i]].sv_srvid));
            //                                }

            assert(memcmp(&services[longest_matching_sid[i / SERVICE_REPLICATION_FACTOR]].sv_srvid,
                    &sref->instance.service.sv_srvid, sizeof(struct service_id)) == 0);
            assert(services[longest_matching_sid[i / SERVICE_REPLICATION_FACTOR]].sv_prefix_bits
                    == sref->instance.service.sv_prefix_bits);

        }

    }

    return;

    assert(service_table_size(&table) == 0);
    assert(total_count == 0);
    /*test a default value */
    uint8_t oprefix = references[0].instance.service.sv_prefix_bits;
    references[0].instance.service.sv_prefix_bits = 0;
    service_table_add_service_reference(&table, &references[0]);

    for(i = 0; i < UNIQUE_SERVICE_REFERENCES; i++) {
        ref = references + i;
        assert(service_table_resolve_service(&table, ref->instance.service.sv_flags,
                ref->instance.service.sv_prefix_bits, &ref->instance.service.sv_srvid)
                == &references[0]);
    }

    ref = &references[0];
    assert(service_table_remove_service_reference(&table, ref->instance.service.sv_flags,
            ref->instance.service.sv_prefix_bits, &ref->instance.service.sv_srvid,
            (struct net_addr*) &ref->instance.address.sin.sin_addr, &sref) >= 0);
    assert(sref == ref);
    assert(service_table_size(&table) == 0);

    references[0].instance.service.sv_prefix_bits = oprefix;

    //    for(i = 0; i < 256; i++) {
    //        assert(prefix_trie_find(&trie, services[i].sv_srvid.srv_un.un_id8,
    //                services[i].sv_prefix_bits) == NULL);
    //    }

    printf("before inserting and iter remove\n");
    //print_trie(&trie);

    /* insert and test iter remove*/
    for(i = 0; i < UNIQUE_SERVICE_REFERENCES; i++) {
        matched[i] = 0;
    }

    for(i = 0; i < UNIQUE_SERVICE_REFERENCES; i++) {
        /* no default */
        ref = &references[i];
        assert(service_table_add_service_reference(&table, ref) > 0);

        assert(service_table_find_service_reference(&table, ref->instance.service.sv_flags,
                ref->instance.service.sv_prefix_bits, &ref->instance.service.sv_srvid,
                (struct net_addr*) &ref->instance.address.sin.sin_addr) == ref);

        total_count++;
        assert(service_table_size(&table) == total_count);
    }

    printf("after insert before iter remove\n");
    //print_trie(&trie);

    /*iter remove*/

    bzero(&iter, sizeof(iter));
    service_table_iter_init(&iter, &table);

    longest = -1;
    i = 0;
    size_t tcount = 0;
    count = 0;
    while(service_table_iter_next(&iter, &ref)) {
        assert(ref);
        printf("Iter remove the next service reference: %s\n", service_id_to_str(
                &ref->instance.service.sv_srvid));
        i++;
        assert(service_table_find_service_reference(&table, ref->instance.service.sv_flags,
                ref->instance.service.sv_prefix_bits, &ref->instance.service.sv_srvid,
                (struct net_addr*) &ref->instance.address.sin.sin_addr) == ref);
        assert(find_unique_service_reference(ref, matched));
        //        printf("next service: %u %s\n", ref->instance.service.sv_prefix_bits, service_id_to_str(
        //                &ref->instance.service.sv_srvid));

        if(count == 0) {
            assert(service_table_find_service_references(&table, ref->instance.service.sv_flags,
                    ref->instance.service.sv_prefix_bits, &ref->instance.service.sv_srvid, &refs,
                    &count) == 0);
            for(k = 0; k < count; k++) {
                sref = refs[k];
                assert(memcmp(&ref->instance.service.sv_srvid, &sref->instance.service.sv_srvid,
                        sizeof(struct service_id)) == 0);
                assert(ref->instance.service.sv_prefix_bits
                        == sref->instance.service.sv_prefix_bits);
            }
            free(refs);
        }

        service_table_iter_remove(&iter, &sref);
        assert(ref == sref);

        total_count--;
        assert(service_table_size(&table) == total_count);
        assert(service_table_find_service_reference(&table, ref->instance.service.sv_flags,
                ref->instance.service.sv_prefix_bits, &ref->instance.service.sv_srvid,
                (struct net_addr*) &ref->instance.address.sin.sin_addr) == NULL);

        //print_trie(&trie);
        assert(service_table_find_service_references(&table, ref->instance.service.sv_flags,
                ref->instance.service.sv_prefix_bits, &ref->instance.service.sv_srvid, &refs,
                &tcount) == 0);

        if(tcount > 0) {
            assert(refs);
            for(k = 0; k < tcount; k++) {
                sref = refs[k];
                assert(memcmp(&ref->instance.service.sv_srvid, &sref->instance.service.sv_srvid,
                        sizeof(struct service_id)) == 0);
                assert(ref->instance.service.sv_prefix_bits
                        == sref->instance.service.sv_prefix_bits);
            }
            free(refs);
        }

        //printf("Post remove ref count: %i decremented ref count: %i\n", tcount, count - 1);
        assert(tcount == --count);

    }

    printf("total iter/remove iterations: %u\n", i);
    assert(0 == service_table_size(&table));
    assert(i == UNIQUE_SERVICE_REFERENCES);
    service_table_iter_destroy(&iter);

    //print_trie(&trie);
    service_table_finalize(&table);

}
int main(int argc, char **argv) {

    srand(92750208);

    initialize_service_references();
    test_service_table();

    return 0;
}
