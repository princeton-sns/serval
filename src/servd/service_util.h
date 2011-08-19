/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * service_util.h
 *
 *  Created on: Feb 11, 2011
 *      Author: daveds
 */

#ifndef SERVICE_UTIL_H_
#define SERVICE_UTIL_H_

#include <netinet/serval.h>
#include <serval/hash.h>
#include <libstack/resolver_protocol.h>
#include <libstack/ctrlmsg.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>

#include "service_types.h"
#include "service_table.h"

#define SERVICE_HASH_PREFIX 96

void init_rand(unsigned int seed);
void init_description_from_reference(struct service_desc *sdesc,
				     struct service_reference *ref);
void init_resolution_from_reference(struct service_info *res,
				    struct service_reference *ref);

uint32_t service_id_prefix_hash(const void *key);

int service_id_prefix_equal(const void *keyA, const void *keyB);

int make_async(int fd);
int set_reuse_ok(int soc);
void
init_control_header(struct sv_control_header *header, uint8_t type,
		    uint32_t xid, uint16_t len);
void initialize_service_id(struct service_id *sid, uint16_t prefix);

int is_bitstring_equal(uint8_t * strA, uint8_t * strB, uint16_t offset,
		       uint16_t len);
uint16_t find_longest_common_prefix(uint8_t * strA, uint8_t * strB,
				    uint16_t offset, uint16_t len);
uint8_t extract_bit_value(uint8_t pos, uint8_t len, uint8_t * key);

char *print_control_message(struct sv_control_header *header, int len);

#endif				/* SERVICE_UTIL_H_ */
