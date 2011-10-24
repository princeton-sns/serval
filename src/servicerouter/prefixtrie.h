/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Copyright 2010 Andrea Mazzoleni. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY ANDREA MAZZOLENI AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL ANDREA MAZZOLENI OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __PREFIXTRIE_H
#define __PREFIXTRIE_H

#include <stdint.h>
#include <unistd.h>
/******************************************************************************/
/* prefix trie */

/**
 * Implements a longest-prefix match trie that returns the best exact
 * prefix match, which is slightly different from the generic trie's
 * longest-bit-string match property which works on fully specified
 * keys (not key prefixes) which is more like a suffix match, i.e.
 * the bamboo/pastry DHT binary tree match.
 *
 * Only one value is allowed per prefix key (not a multi-set)
 *
 * Fixed level compression at each internal node of the tree
 * A burst trie with path compression may be more efficient, but this is a
 * simpler first approx.
 *
 * 64 byte cache line with 64 bit pointers = branching factor of 8
 * 64 byte cache line with 32 bit pointers = branching factor of 16
 *
 * However, we need a * match for each possible bit string, which means
 * for a branch factor of 8, we need 1 (***) + 2 (0**, 1**) + 4 (00*,01*,10*,11*)
 * prefix match pointers, which gives 15 pointers in all, or
 * 2^(log(PREFIX_TRIE_BRANCH) + 1) - 1 pointers
 */

//typedef tommy_node prefix_trie_node;

#define PREFIX_TRIE_ROOT_BRANCH 16
#define PREFIX_TRIE_ROOT_BIT 4
/*unless we increase the size of the node struct, this is our limit*/
#define PREFIX_TRIE_MAX_BIT 5

struct prefix_trie_data;
struct prefix_trie_node;

struct prefix_trie_iter_node {
    struct prefix_trie_iter_node *prev;
    struct prefix_trie_node *node;
    int level;
    struct prefix_trie_data **branches;
    int limit;
    int branch;
    int last_branch;
    int len;
    struct prefix_trie_data *prefix;
};
struct prefix_trie_struct {
    size_t key_len;
    size_t count; /** leaves (values, including conflicting prefixes) */
    size_t node_count; /** internal nodes */
    void *def_value; /** default value - * match */
    float fill_factor; /** >= fill_factor means expand the branch, < ff/2 means split*/
    size_t max_depth;
    uint16_t shortest;
    uint16_t branch_fill;
    struct prefix_trie_data *root_branch[PREFIX_TRIE_ROOT_BRANCH];
    /* density, expanse? */
    //tommy_allocator* alloc; /**< Allocator for internal nodes. */
};
struct prefix_trie_iter {
    struct prefix_trie_iter_node *iter_node;
    struct prefix_trie_iter_node last_iter_node;
    struct prefix_trie_struct *trie;
};

/**
 * Initializes the trie.
 * You have to provide an allocator initialized with *both* the size and align with TOMMY_TRIE_BLOCK_SIZE.
 * You can share this allocator with other tries.
 * \param alloc Allocator initialized with *both* the size and align with TOMMY_TRIE_BLOCK_SIZE.
 */
int prefix_trie_initialize(struct prefix_trie_struct *trie, size_t keylen,
			   float fill_factor);

/**
 * Deinitializes the trie.
 */
int prefix_trie_finalize(struct prefix_trie_struct *trie);

/**
 * Inserts an element in the trie.
 * You have to provide the pointer of the node embedded into the object,
 * the pointer at the object and the key to use.
 * \param node Pointer at the node embedded into the object to insert.
 * \param data Pointer at the object to insert.
 * \param key Key to use to insert the object.
 */
void
*prefix_trie_insert(struct prefix_trie_struct *trie, uint8_t * key,
		    uint16_t prefix, void *data);

/**
 * Searches and removes the first element with the specified key.
 * If the element is not found, 0 is returned.
 * If more equal elements are present, the first one is removed. 
 * This operation is faster than calling prefix_trie_bucket() and prefix_trie_remove_existing() separately.
 * \param key Key of the element to find and remove.
 * \return The removed element, or 0 if not found.
 */
void *prefix_trie_remove(struct prefix_trie_struct *trie, uint8_t * key,
			 uint16_t prefix);

/**
 * Searches an element in the trie.
 * You have to provide the key of the element you want to find.
 * If more elements with the same key are present, the first one is returned.
 * \param key Key of the element to find.
 * \return The first element found, or 0 if none.
 */
void *prefix_trie_find(struct prefix_trie_struct *trie, uint8_t * key,
		       uint16_t prefix);
void *prefix_trie_find_exact(struct prefix_trie_struct *trie,
			     uint8_t * key, uint16_t prefix);
int prefix_trie_has_key(struct prefix_trie_struct *trie, uint8_t * key,
			uint16_t prefix);

void prefix_trie_iter_init(struct prefix_trie_iter *iter,
			   struct prefix_trie_struct *trie);
int prefix_trie_iter_next(struct prefix_trie_iter *iter, uint8_t ** key,
			  uint16_t * prefix, void **data);
int prefix_trie_iter_next_print(struct prefix_trie_iter *iter,
				uint8_t ** key, uint16_t * prefix, void **data);
int prefix_trie_iter_remove(struct prefix_trie_iter *iter);

void prefix_trie_iter_destroy(struct prefix_trie_iter *iter);

void print_trie(struct prefix_trie_struct *trie);
char *print_trie_data(struct prefix_trie_data *dnode);
char *print_trie_node(struct prefix_trie_node *node, uint8_t offset);

/**
 * Returns the number of elements.
 */
uint32_t prefix_trie_count(struct prefix_trie_struct *trie);
uint32_t prefix_trie_node_count(struct prefix_trie_struct *trie);
#endif
