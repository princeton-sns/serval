/*
 * service_util.c
 *
 *  Created on: Feb 11, 2011
 *      Author: daveds
 */
#include "service_util.h"
#include "service_table.h"
#include "serval/platform.h"
#include <glib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include "cmwc.h"
#include "debug.h"

#define SERVICE_HASH_PREFIX_BYTES SERVICE_HASH_PREFIX / 8

void init_rand(unsigned int seed) {
    srand(seed);
    int i = 0;
    for(i = 0; i < 4096; i++) {
        Q[i] = (long) (((float) rand() / RAND_MAX) * 0xFFFFFFFF);
    }

}

/* find the longest prefix match in a byte starting from the MSB edge to limit*/
static inline uint16_t check_byte_bits(uint8_t byteA, uint8_t byteB, int limit) {

    /*match starting from the most sig bit*/
    uint16_t prefix = 0;
    int i = 1;
    for(; i <= limit; i++) {
        if(((byteA) & (0x80)) == ((byteB) & (0x80))) {
            prefix++;
            byteA <<= 1;
            byteB <<= 1;
        } else {
            return prefix;
        }
    }
    return prefix;
}

/**
 *  extract len bits from key byte string starting at bit position p
 *  0 < len <= 5 (at most a 5 bit string)
 */
inline uint8_t extract_bit_value(uint8_t pos, uint8_t len, uint8_t* key) {
    assert(len <= 8);
    if(len == 0) {
        return 0;
    }
    uint8_t shift_bits = pos % 8;
    pos = pos / 8;
    return ((uint8_t) (key[pos] << shift_bits) >> (8 - len))
            | (shift_bits + len > 8 ? (key[pos + 1] >> (16 - shift_bits - len)) : 0);
}

int is_bitstring_equal(uint8_t* strA, uint8_t* strB, uint16_t offset, uint16_t len) {

    if(len == 0) {
        return TRUE;
    }
    if(len < 0) {
        return FALSE;
    }
    //    char buffer[128];
    //    printf("is bitstring equal from: %u to %u, bits1 %s\n", offset, offset + len, __hexdump(strA,
    //            32, buffer, 128));

    /*initial bits to skip - modulo 8*/
    uint16_t shift_bits = offset & 0x0007;
    /*first byte to compare*/
    offset = offset / 8;
    /*full bytes to compare*/
    uint16_t byte_len = (len - (shift_bits > 0 ? 8 - shift_bits : 0)) / 8;

    //    printf("is bitstring equal shift: %u offset %u, byte len %u, bits2 %s\n", shift_bits, offset,
    //            byte_len, __hexdump(strB, 32, buffer, 128));

    if(shift_bits + len > 8 && (shift_bits == 0 || (uint8_t) (strA[offset] << shift_bits)
            >> shift_bits == (uint8_t) (strB[offset] << shift_bits) >> shift_bits)) {
        if(shift_bits > 0) {
            offset++;
        }

        /*tail end of the bits to compare*/
        shift_bits = 8 - ((len - 8 + shift_bits) % 8);

        /*compare bytes */
        //        printf("comparing bytes: %u to %u? %i\n", offset, byte_len, memcmp(strA + offset, strB
        //                + offset, byte_len));
        if(byte_len == 0 || (memcmp(strA + offset, strB + offset, byte_len) == 0)) {
            /*no trailing bits*/
            if(shift_bits == 8) {
                return TRUE;
            }

            return strA[offset + byte_len] >> shift_bits == strB[offset + byte_len] >> shift_bits;
        }
    } else {
        /*check each bit - first byte match failed*/
        //printf("first byte check failed, check bits\n");
        int val = check_byte_bits(strA[offset] << shift_bits, strB[offset] << shift_bits,
                (shift_bits + len > 8 ? 8 - shift_bits : len));
        return val == (shift_bits + len > 8 ? 8 - shift_bits : len);
    }
    return 0;
}

uint16_t find_longest_common_prefix(uint8_t* strA, uint8_t* strB, uint16_t offset, uint16_t len) {
    if(len == 0) {
        return 0;
    }

    uint16_t shift_bits = offset % 8;
    offset = offset / 8;
    uint16_t byte_end = offset + (len + shift_bits) / 8;

    uint16_t prefix = 0;

    //printf("shift_bits: %u, offset: %u, byte_end: %u len: %u\n", shift_bits, offset, byte_end, len);

    if(len + shift_bits > 8 && (shift_bits == 0 || (uint8_t) (strA[offset] << shift_bits)
            >> shift_bits == (uint8_t) (strB[offset] << shift_bits) >> shift_bits)) {

        /*initial bits matched*/
        if(shift_bits > 0) {
            prefix += (8 - shift_bits);
            offset++;
        }

        shift_bits = (8 - ((len - 8 + shift_bits) % 8)) % 8;

        //printf("re-shift %u prefix %u offset %u\n", shift_bits, prefix, offset);
        int i = offset;
        for(; i < byte_end; i++) {
            if(strA[i] == strB[i]) {
                prefix += 8;
            } else {
                //printf("failed byte check at %i\n", i);
                prefix += check_byte_bits(strA[i], strB[i], 8);
                return prefix;
            }
        }

        if(shift_bits > 0) {
            //printf("shift at the end\n");
            if(strA[byte_end] >> shift_bits == strB[byte_end] >> shift_bits) {
                prefix += (8 - shift_bits);
                //printf("prefix? %u shift %u\n", prefix, shift_bits);
            } else {
                //printf("check byte bits - mismatch\n");
                prefix += check_byte_bits(strA[byte_end], strB[byte_end], (8 - shift_bits));
            }
        }
    } else {
        /*check each bit - first byte match failed*/
        //printf("first byte check failed, check bits\n");
        prefix = check_byte_bits(strA[offset] << shift_bits, strB[offset] << shift_bits,
                (shift_bits + len > 8 ? 8 - shift_bits : len));
    }

    return prefix;
}
void init_resolution_from_reference(struct service_resolution*res, struct service_reference*ref) {
    bzero(res, sizeof(*res));

    res->sv_flags = ref->instance.service.sv_flags;
    res->sv_prefix_bits = ref->instance.service.sv_prefix_bits;
    res->priority = ref->priority;
    res->weight = ref->weight;
    res->idle_timeout = ref->idle_timeout;
    res->hard_timeout = ref->hard_timeout;

    memcpy(&res->srvid, &ref->instance.service.sv_srvid, sizeof(struct service_id));
    memcpy(&res->address.net_un.un_ip, &ref->instance.address.sin.sin_addr, sizeof(struct in_addr));

}

void init_description_from_reference(struct service_desc*sdesc, struct service_reference*ref) {
    bzero(sdesc, sizeof(*sdesc));
    sdesc->flags = ref->instance.service.sv_flags;
    sdesc->prefix = ref->instance.service.sv_prefix_bits;
    memcpy(&sdesc->service, &ref->instance.service.sv_srvid, sizeof(struct service_id));
}

uint32_t service_id_prefix_hash(const void* key) {

    if(key == NULL) {
        return 0;
    }

    return full_bitstring_hash(key, SERVICE_HASH_PREFIX);
}

int service_id_prefix_equal(const void* keyA, const void* keyB) {

    if(keyA == keyB) {
        return TRUE;
    }
    if(keyA == NULL) {
        return FALSE;
    }
    if(keyB == NULL) {
        return FALSE;
    }

    return memcmp(keyA, keyB, SERVICE_HASH_PREFIX_BYTES) == 0;
}

int make_async(int fd) {
    int flags;
    if((flags = fcntl(fd, F_GETFL, 0)) < 0) {
        LOG_ERR("F_GETFL error on fd %d (%s)", fd, strerror(errno));
        return -1;
    }
    flags |= O_NONBLOCK;
    if(fcntl(fd, F_SETFL, flags) < 0) {
        LOG_ERR( "F_SETFL error on fd %d (%s)", fd, strerror(errno));
        return -1;
    }
    return 0;
}

int set_reuse_ok(int soc) {
    int option = 1;
    if(setsockopt(soc, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0) {
        LOG_ERR("proxy setsockopt error");
        return -1;
    }
    return 0;
}

void initialize_service_id(struct service_id* sid, uint16_t prefix) {

    /*generate random bytes*/

    int offset = prefix / 8;
    int size = sizeof(*sid);

    assert(offset <= size);
    if(offset == size) {
        return;
    }

    uint8_t mask = 0xFF >> (prefix % 8);

    /*generate the first val*/
    uint32_t val = rand(); //cmwc4096();
    uint8_t idb = sid->srv_un.un_id8[offset];
    sid->srv_un.un_id8[offset++] = (idb & ~mask) | ((((uint8_t*) &val)[0]) & mask);

    int b_ind = 1;
    uint8_t bval = 0;
    while(offset < size) {
        if(b_ind == 4) {
            val = rand();//cmwc4096();
            b_ind = 0;
        }
        bval = ((uint8_t*) &val)[b_ind++];
        sid->srv_un.un_id8[offset++] = bval;
    }
}

inline void init_control_header(struct sv_control_header* header, uint8_t type, uint32_t xid,
        uint16_t len) {
    assert(header);
    header->version = SV_VERSION;
    header->type = type;
    header->xid = htonl(xid);
    header->length = htons(len);
}

char* print_control_message(struct sv_control_header* header, int len) {
    assert(header);
    static char buffer[1024];

    __hexdump(header, len, buffer, 1024);
    return buffer;
}

