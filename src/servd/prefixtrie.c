/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include "prefixtrie.h"
#include "debug.h"
#include "service_util.h"
#include "netinet/serval.h"
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
/******************************************************************************/
/* trie */

/**
 * Prefixtrie tree.
 * A tree contains TOMMY_TRIE_TREE_MAX ordered pointers to <null/node/tree>.
 *
 * Each tree level uses exactly TOMMY_TRIE_TREE_BIT bits from the key.
 */

/** default root branching factor = 16, 4 bit buckets */

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif
/**
 * Get and set pointer of trie nodes.
 * The pointer type is stored in the lower bit.
 * Memory must be aligned!!
 */

/*for simplicity - not minimal storage - otherwise diff leaf and prefix nodes */
/*16 (28) bytes
 * 256 bit key len limit
 * */
struct prefix_trie_data {
    uint8_t *key;
    uint8_t len;
    uint8_t shortest;
    uint16_t ref_count;
    struct prefix_trie_data *prefix;
    void *data;
};

/* factor: 1 bit for type, 3 bits for branching (up to 7 = 128-ary), 6 bits for fill, 6 bits for full: 64-ary */
/* having 3 bytes would be best: type, branching, "full ind" in byte 1, and fill, full count in their own separate bytes
 * to allow for up to 7 bit branching and fill/full up to 128.
 * */
#define set_node_type(node) ((node)->factor |= 0x8000)

#define get_branch_bits(node) ((node)->factor >> 12 & 0x7)
#define set_branch_bits(node, bits) ((node)->factor = ((bits) << 12 | 0x8000) | ((node)->factor & 0x80FF))

#define get_branch_fill(node) ((node)->factor >> 6 & 0x3F)
#define set_branch_fill(node, fill) ((node)->factor = ((node)->factor & 0xF03F) | ((fill) & 0x3F) << 6)

#define get_branch_full(node) ((node)->factor & 0x3F)
#define set_branch_full(node, fill) ((node)->factor = ((node)->factor & 0xFFC0) | ((fill) & 0x3F))

/*cannot exceed 255 or dip below 0*/
#define inc_branch_fill(node) set_branch_fill(node, get_branch_fill(node) + 1)
#define dec_branch_fill(node) set_branch_fill(node, get_branch_fill(node) - 1)

#define inc_branch_full(node) (node)->factor++
#define dec_branch_full(node) (node)->factor--

/* 20 (36) bytes - min 2 branch pointers*/
struct prefix_trie_node {
    uint8_t *key;
    uint8_t skip;
    uint8_t shortest;
    uint16_t factor;
    struct prefix_trie_data *prefix;
    struct prefix_trie_data *branches[0];
};

/**
 * Trie node types
 */
#define PREFIX_TRIE_TYPE_DATA 0
#define PREFIX_TRIE_TYPE_NODE 1

#define trie_get_type(ptr) ((ptr)->ref_count & 0x8000)

static inline void destroy_iter_node_list(struct prefix_trie_iter_node
                                          *inode)
{
    struct prefix_trie_iter_node *temp = NULL;
    while (inode) {
        temp = inode->prev;
        free(inode);
        inode = temp;
    }
}

static inline struct prefix_trie_iter_node *create_iter_node(uint16_t
                                                             total_bits, struct
                                                             prefix_trie_data
                                                             **branches,
                                                             uint8_t
                                                             branch_index,
                                                             uint8_t level,
                                                             struct
                                                             prefix_trie_node
                                                             *node, struct
                                                             prefix_trie_iter_node
                                                             *prev)
{
    /*TODO - slab allocation? */
    struct prefix_trie_iter_node *inode =
        (struct prefix_trie_iter_node *) malloc(sizeof(*inode));
    bzero(inode, sizeof(*inode));
    inode->branches = branches;
    inode->branch = branch_index;
    inode->node = node;
    inode->prev = prev;
    inode->limit = node ? 1 << get_branch_bits(node) : PREFIX_TRIE_ROOT_BRANCH;
    inode->level = level;
    inode->len = total_bits;
    return inode;
}

static inline struct prefix_trie_data *last_prefix_of(struct
                                                      prefix_trie_data
                                                      *node, uint16_t minlen)
{
    assert(node);
    while (node->prefix && node->prefix->len > minlen) {
        node = node->prefix;
    }

    return node;
}

static inline uint16_t get_branch_index(struct prefix_trie_data *leaf,
                                        uint8_t offset, uint8_t bits)
{
    assert(leaf);

    if (trie_get_type(leaf) != PREFIX_TRIE_TYPE_DATA
        || bits <= leaf->len - offset) {
        return extract_bit_value(offset, bits, leaf->key);
    }
    return extract_bit_value(offset, leaf->len - offset,
                             leaf->key) << (bits - leaf->len + offset);

}

static inline void set_branch_child(struct prefix_trie_struct *trie,
                                    struct prefix_trie_node *parent,
                                    struct prefix_trie_data **branches,
                                    int branch_index,
                                    struct prefix_trie_data *node)
{
    assert(branches);

    int filled = branches[branch_index] != NULL;

    if (branches[branch_index]
        && trie_get_type(branches[branch_index]) == PREFIX_TRIE_TYPE_DATA) {
        branches[branch_index]->ref_count--;
        assert(branches[branch_index]->ref_count != 0xFFFF);
    }

    branches[branch_index] = node;

    if (node) {

        if (parent) {
            if (!filled) {
                inc_branch_fill(parent);
            }
            if (node->shortest < parent->shortest) {
                parent->shortest = node->shortest;
            }
        } else if (!filled) {
            trie->branch_fill++;
        }

        if (trie_get_type(node) == PREFIX_TRIE_TYPE_DATA) {
            node->ref_count++;
        }

    } else if (filled) {
        if (parent) {
            dec_branch_fill(parent);
        } else {
            trie->branch_fill--;
        }
    }
    /*if the replaced entry contained the shortest prefix, rely on external mechanisms to update
     * parent's shortest prefix*/

}

static inline int set_node_prefix(struct prefix_trie_data *node,
                                  struct prefix_trie_data *prefix)
{
    if (node == NULL) {
        return FALSE;
    }

    int unlinked = FALSE;

    if (node->prefix) {
        node->prefix->ref_count--;
        assert(node->prefix->ref_count != 0xFFFF);

        unlinked = node->prefix->ref_count == 0;
    }

    node->prefix = prefix;

    if (prefix) {
        prefix->ref_count++;

        if (prefix->shortest < node->shortest) {
            node->shortest = prefix->shortest;
        }
    }

    return unlinked;
}

static inline void destroy_trie_node(struct prefix_trie_struct *trie,
                                     struct prefix_trie_data *leaf)
{
    assert(trie);
    assert(leaf);
    set_node_prefix(leaf, NULL);

    if (trie_get_type(leaf) == PREFIX_TRIE_TYPE_DATA) {
        assert(leaf->ref_count == 0);
        trie->count--;
    } else {
        /*null all child references */
        struct prefix_trie_node *node = (struct prefix_trie_node *) leaf;
        if (get_branch_fill(node) > 0) {
            int i = 0;
            for (; i < 1 << get_branch_bits(node); i++) {
                set_branch_child(trie, node, node->branches, i, NULL);
            }
        }
        assert(get_branch_fill(node) == 0);
        trie->node_count--;
    }

    free(leaf);
}

static inline struct prefix_trie_data *
create_trie_data(struct prefix_trie_struct *trie,
                 uint8_t *key,
                 uint16_t len,
                 void *data, 
                 struct prefix_trie_data *prefix)
{
    struct prefix_trie_data *trie_data =
        (struct prefix_trie_data *) malloc(sizeof(*trie_data));
    bzero(trie_data, sizeof(*trie_data));

    trie_data->key = key;
    /*full prefix length */
    trie_data->len = len;
    trie_data->shortest = len;
    trie_data->data = data;

    set_node_prefix(trie_data, prefix);

    trie->count++;
    return trie_data;
}

static inline struct prefix_trie_node *create_trie_node(struct
                                                        prefix_trie_struct
                                                        *trie,
                                                        uint8_t branch,
                                                        uint16_t skip,
                                                        uint8_t * key, struct
                                                        prefix_trie_data
                                                        *prefix)
{

    int size =
        sizeof(struct prefix_trie_node) +
        (1 << branch) * sizeof(struct prefix_trie_data *);
    struct prefix_trie_node *node = (struct prefix_trie_node *) malloc(size);
    bzero(node, size);

    set_node_type(node);
    set_branch_bits(node, branch);
    /*skipped bits between the node's parent and the node itself */
    node->skip = skip;
    node->key = key;
    node->shortest = 0xFF;

    set_node_prefix((struct prefix_trie_data *) node, prefix);

    trie->node_count++;
    assert(trie_get_type((struct prefix_trie_data *) node) !=
           PREFIX_TRIE_TYPE_DATA);
    return node;
}

/* a node is full only if there exists entries on either "half" of its branches and it's skip = 0 - i.e. the next bit*/
static inline int is_node_full(struct prefix_trie_data *dnode)
{
    if (dnode == NULL) {
        return FALSE;
    }

    if (trie_get_type(dnode) == PREFIX_TRIE_TYPE_DATA) {
        return FALSE;
    }

    struct prefix_trie_node *node = (struct prefix_trie_node *) dnode;

    if (node->skip > 0) {
        return FALSE;
    }

    /*half-way marker of the branches */
    uint8_t marker = 1 << (get_branch_bits(node) - 1);
    uint8_t fill = get_branch_fill(node);

    /*singleton nodes are disallowed */
    assert(fill > 1);

    /*more than half the branches are occupied, so there must be branches on either side */
    if (fill > marker) {
        return TRUE;
    }

    uint8_t left = 0;
    int i = 0;
    for (; i < marker; i++) {
        if (node->branches[i]) {
            left++;
        } else if (left && (fill - left) + i >= marker) {
            return TRUE;
        }
    }

    //return FALSE;
    return fill - left > 0;
}

/*split a node into a left branch*/
static inline struct prefix_trie_data *split_node(struct prefix_trie_struct
                                                  *trie, struct prefix_trie_node
                                                  *node, int left)
{
    assert(node);

    /*the new split node bit */
    uint8_t bits = get_branch_bits(node) - 1;
    uint8_t i = (left ? 0 : 1 << bits);
    uint8_t end = (left ? 1 << bits : 1 << (bits + 1));

    uint8_t mask = 0xFF >> (8 - bits);
    if (bits == 0) {
        if (left) {
            return node->branches[0];
        }
        return node->branches[1];
    }

    struct prefix_trie_node *newnode =
        create_trie_node(trie, bits, 0, NULL, node->prefix);
    struct prefix_trie_data *dleaf = NULL;
    for (; i < end; i++) {
        if (node->branches[i]) {
            dleaf = node->branches[i];
            set_branch_child(trie, newnode, newnode->branches, i & mask, dleaf);
            if (is_node_full(dleaf)) {
                inc_branch_full(newnode);
            }
            newnode->key = dleaf->key;
        }
    }

    if (get_branch_fill(newnode) == 0) {
        /*no leaves on this side of the node */
        destroy_trie_node(trie, (struct prefix_trie_data *) newnode);
        return NULL;
    }

    if (get_branch_fill(newnode) == 1) {
        /*replace with the lone leaf data node */
        //printf("start: %i i: %i end: %i mask: %u\n", (left ? 0 : 1 << bits), i, end, mask);
        //printf("replacing new node: %s with lone leaf: %s\n", print_trie_node(newnode, 0),print_trie_data(dleaf));
        /*need to update the skip bits of the child to reflect the "missing" parent */
        if (trie_get_type(dleaf) != PREFIX_TRIE_TYPE_DATA) {
            ((struct prefix_trie_node *) dleaf)->skip += bits;
        }
        destroy_trie_node(trie, (struct prefix_trie_data *) newnode);
        return dleaf;
    }

    return (struct prefix_trie_data *) newnode;
}

static inline struct prefix_trie_node *split_path(struct prefix_trie_struct
                                                  *trie,
                                                  uint8_t total_bits,
                                                  uint8_t common_prefix,
                                                  struct prefix_trie_data
                                                  *next, uint8_t * key,
                                                  uint16_t prefix, void *data)
{

    uint8_t bits = 1;
    uint8_t brind = 0;
    short node_full = FALSE;

    //printf("splitting node: tbits %u cprefix %u node? %u %s\n", total_bits, common_prefix,trie_get_type(next), print_trie_data(next));
    if (trie_get_type(next) != PREFIX_TRIE_TYPE_DATA) {
        struct prefix_trie_node *node = (struct prefix_trie_node *) next;
        node->skip -= (common_prefix + 1);
        node_full = is_node_full((struct prefix_trie_data *) node);
        /* check additional fill, since we know we are potentially doubling from 1->2 bits,
         * we can check for the explict fill factor of 3/4 */
        if (node_full && trie->fill_factor <= 0.75f) {
            bits = 2;
        }
        //printf("splitting existing node, new skip %u isfull %i\n", node->skip, node_full);
    }

    struct prefix_trie_data *dprefix = (next->prefix
                                        && next->prefix->len <=
                                        total_bits +
                                        common_prefix ? next->prefix : NULL);

    struct prefix_trie_data *newleaf =
        create_trie_data(trie, key, prefix, data, dprefix);
    struct prefix_trie_node *newnode =
        create_trie_node(trie, bits, common_prefix, key, dprefix);

    if (bits == 1) {
        brind = get_branch_index(next, total_bits + common_prefix, bits);
        //printf("branch index of existing node in the split node: %i\n", brind);
        set_branch_child(trie, newnode, newnode->branches, brind, next);
        if (node_full) {
            inc_branch_full(newnode);
        }
    } else {
        //printf("subsuming the node!\n");
        /*subsume the node - doubling the new split node by splitting the child: next */
        struct prefix_trie_data *nodeA = NULL;
        struct prefix_trie_data *nodeB = NULL;

        nodeA = split_node(trie, (struct prefix_trie_node *) next, TRUE);
        nodeB = split_node(trie, (struct prefix_trie_node *) next, FALSE);

        /* TODO it may be best to both steal a node->factor bit for indicating fullness
         * and allow set_branch_child to auto inc/dec the parent's full counter
         */
        if (nodeA) {
            set_branch_child(trie, newnode, newnode->branches,
                             get_branch_index(nodeA,
                                              total_bits + common_prefix,
                                              bits), nodeA);
            if (is_node_full(nodeA)) {
                inc_branch_full(newnode);
            }
        }

        if (nodeB) {
            set_branch_child(trie, newnode, newnode->branches,
                             get_branch_index(nodeB,
                                              total_bits + common_prefix,
                                              bits), nodeB);
            if (is_node_full(nodeB)) {
                inc_branch_full(newnode);
            }
        }

        destroy_trie_node(trie, next);
    }

    brind = get_branch_index(newleaf, total_bits + common_prefix, bits);
    //printf("branch index of new leaf node in the split node: %i\n", brind);
    set_branch_child(trie, newnode, newnode->branches, brind, newleaf);

    assert(trie_get_type((struct prefix_trie_data *) newnode) !=
           PREFIX_TRIE_TYPE_DATA);
    return newnode;
}

static inline int should_double(struct prefix_trie_struct *trie,
                                struct prefix_trie_node *node)
{
    assert(trie);
    if (node == NULL) {
        return FALSE;
    }
    uint8_t bits = get_branch_bits(node);
    return bits < PREFIX_TRIE_MAX_BIT
        && (get_branch_fill(node) + get_branch_full(node))
        / (float) (1 << (bits + 1)) >= trie->fill_factor;
}

static inline struct prefix_trie_node *double_node(struct
                                                   prefix_trie_struct
                                                   *trie, struct prefix_trie_node
                                                   *node, uint8_t offset)
{
    assert(trie && node);
    /*note that doubling does not change the node's full state */
    uint8_t bits = get_branch_bits(node) + 1;

    struct prefix_trie_node *newnode =
        create_trie_node(trie, bits, node->skip, node->key,
                         node->prefix);

    //printf("Doubling node to %u bits\n", bits);

    struct prefix_trie_node *bnode;
    struct prefix_trie_data *branch;
    struct prefix_trie_data *spbranch;
    int i = 0;
    uint16_t newbranch = 0;

    for (; i < 1 << (bits - 1); i++) {
        branch = node->branches[i];
        if (branch) {
            newbranch = get_branch_index(branch, offset, bits);

            if (trie_get_type(branch) == PREFIX_TRIE_TYPE_DATA) {

                //printf("setting branch ind from %u to %u\n", i, newbranch);
                set_branch_child(trie, newnode, newnode->branches,
                                 newbranch, branch);
            } else {
                bnode = (struct prefix_trie_node *) branch;
                if (bnode->skip > 0) {
                    //printf("setting branch ind from %u to %u\n", i, newbranch);
                    bnode->skip--;
                    set_branch_child(trie, newnode, newnode->branches,
                                     newbranch, branch);
                    if (is_node_full((struct prefix_trie_data *) bnode)) {
                        inc_branch_full(newnode);
                    }
                } else {
                    //printf("splitting double node's child node: %s\n", print_trie_node(bnode,offset));
                    spbranch = split_node(trie, bnode, TRUE);
                    if (spbranch) {
                        newbranch = get_branch_index(spbranch, offset, bits);
                        //printf("setting branch ind from %u to %u\n", i, newbranch);

                        set_branch_child(trie, newnode, newnode->branches,
                                         newbranch, spbranch);

                        if (is_node_full((struct prefix_trie_data *) spbranch)) {
                            inc_branch_full(newnode);
                        }
                    }

                    spbranch = split_node(trie, bnode, FALSE);
                    if (spbranch) {
                        newbranch = get_branch_index(spbranch, offset, bits);
                        //printf("setting branch ind from %u to %u\n", i, newbranch);
                        set_branch_child(trie, newnode, newnode->branches,
                                         newbranch, spbranch);

                        if (is_node_full((struct prefix_trie_data *) spbranch)) {
                            inc_branch_full(newnode);
                        }
                    }

                    /* ensure that the node->branch reference is properly removed */
                    set_branch_child(trie, node, node->branches, i, NULL);
                    destroy_trie_node(trie, branch);
                }
            }
        }
    }

    //printf("doubled node: %s\n", print_trie_node(newnode, offset));
    return newnode;
}

static inline int should_halve(struct prefix_trie_struct *trie,
                               struct prefix_trie_node *node)
{
    assert(trie);
    if (node == NULL) {
        return FALSE;
    }
    uint8_t bits = get_branch_bits(node);
    return bits > 1
        && (get_branch_fill(node) / (float) (1 << bits) <
            trie->fill_factor / 2);
}

static inline int check_shifted(struct prefix_trie_node *node)
{
    assert(node);
    /*there are only 2 branches in the node */
    int first = -1;
    int i = 0;
    for (; i < get_branch_bits(node); i++) {
        if (node->branches[i]) {
            if (first >= 0) {
                if (i == first + 1) {
                    if (first % 2 == 0) {
                        return first;
                    }
                    return -1;
                }
                return -1;
            } else {
                first = i;
            }
        }
    }

    return -1;
}

static inline struct prefix_trie_data *halve_node(struct prefix_trie_struct
                                                  *trie, struct prefix_trie_node
                                                  *node)
{
    assert(trie && node);
    struct prefix_trie_data *child;
    uint8_t bits = get_branch_bits(node);
    uint8_t fill = get_branch_fill(node);
    short shift_ind = -1;

    if (fill == 1) {
        /*return the one child */
        int i = 0;
        for (; i < 1 << bits; i++) {
            if (node->branches[i]) {
                child = node->branches[i];
                //destroy_trie_node(trie, (struct prefix_trie_data*) node);
                return child;
            }
        }
        assert(FALSE);
    }

    struct prefix_trie_node *newnode = NULL;
    if (fill > 2 || (shift_ind = check_shifted(node)) < 0) {
        /*create a new node to halve the existing */

        newnode =
            create_trie_node(trie, bits - 1, node->skip, node->key,
                             node->prefix);
        struct prefix_trie_node *hnode = NULL;
        int i = 0;
        for (; i < 1 << bits; i += 2) {
            if (node->branches[i]) {
                if (node->branches[i + 1]) {
                    /*TODO - this may actually generate a doubled node */
                    //hnode = create_trie_node(trie, 1, 0, node->branches[i]->key, node->prefix);
                    hnode =
                        create_trie_node(trie, 1, 0,
                                         node->branches[i]->key, NULL);
                    set_branch_child(trie, hnode, hnode->branches, 0,
                                     node->branches[i]);

                    if (is_node_full(node->branches[i])) {
                        inc_branch_full(hnode);
                    }
                    set_branch_child(trie, hnode, hnode->branches, 1,
                                     node->branches[i + 1]);
                    if (is_node_full(node->branches[i + 1])) {
                        inc_branch_full(hnode);
                    }

                    set_branch_child(trie, newnode, newnode->branches,
                                     i >> 1, (struct prefix_trie_data *) hnode);

                    inc_branch_full(newnode);

                } else {
                    if (trie_get_type(node->branches[i]) !=
                        PREFIX_TRIE_TYPE_DATA) {
                        /*node skip increments by one */
                        ((struct prefix_trie_node *) node->branches[i])->skip++;
                    }
                    set_branch_child(trie, newnode, newnode->branches,
                                     i >> 1, node->branches[i]);
                }
            } else if (node->branches[i + 1]) {
                if (trie_get_type(node->branches[i + 1]) !=
                    PREFIX_TRIE_TYPE_DATA) {
                    /*node skip increments by one */
                    ((struct prefix_trie_node *) node->branches[i + 1])->skip++;
                }
                set_branch_child(trie, newnode, newnode->branches, i >> 1,
                                 node->branches[i + 1]);
            }
        }
    } else {
        /*fill == 2 and all the nodes in a single bit bucket */
        /*TODO may also generate a doubled node */
        newnode =
            create_trie_node(trie, 1, node->skip + bits - 1, NULL,
                             node->prefix);
        set_branch_child(trie, newnode, newnode->branches, 0,
                         node->branches[shift_ind]);
        if (is_node_full(node->branches[shift_ind])) {
            inc_branch_full(newnode);
        }

        set_branch_child(trie, newnode, newnode->branches, 1,
                         node->branches[shift_ind + 1]);
        if (is_node_full(node->branches[shift_ind + 1])) {
            inc_branch_full(newnode);
        }

        newnode->key = newnode->branches[0]->key;
    }

    return (struct prefix_trie_data *) newnode;

}

static inline void update_shortest(struct prefix_trie_struct *trie,
                                   struct prefix_trie_iter_node *inode)
{
    if (inode == NULL) {
        return;
    }
    //printf("updating shortest!\n");

    /*must all be nodes - track back to the top and update the node->shortest by branch */
    uint8_t shortest = 0xFF;
    int i = 0;
    while (inode) {
        for (i = 0; i < inode->limit; i++) {
            if (inode->branches[i]
                && inode->branches[i]->shortest < shortest) {
                shortest = inode->branches[i]->shortest;
            }
        }

        if (inode->node) {
            inode->node->shortest = shortest;
            //printf("new shortest at: %s\n", print_trie_node(inode->node, 0));

        } else {
            trie->shortest = shortest;
        }
        shortest = 0xFF;
        inode = inode->prev;
    }
}

static inline void *search_prefix(struct prefix_trie_data *prefix,
                                  uint8_t * key, uint16_t klen,
                                  uint8_t total_bits, uint8_t * found)
{
    while (prefix) {
        //printf("comparing klen: %u total bits: %u to prefix: %s\n", klen, total_bits, print_trie_data(prefix));
        if (klen >= prefix->len
            && is_bitstring_equal(key, prefix->key, total_bits,
                                  prefix->len - total_bits)) {
            if (found) {
                *found = TRUE;
            }
            return prefix->data;
        }
        prefix = prefix->prefix;
    }

    if (found) {
        *found = FALSE;
    }
    return NULL;
}

static inline void *search_prefix_exact(struct prefix_trie_data *prefix,
                                        uint8_t * key, uint16_t klen,
                                        uint8_t total_bits, uint8_t * found)
{
    while (prefix) {
        if (klen == prefix->len
            && is_bitstring_equal(key, prefix->key, total_bits,
                                  prefix->len - total_bits)) {
            if (found) {
                *found = TRUE;
            }
            return prefix->data;
        }
        prefix = prefix->prefix;
    }

    if (found) {
        *found = FALSE;
    }
    return NULL;
}

static inline struct prefix_trie_data *find_singleton_child(struct
                                                            prefix_trie_node
                                                            *node)
{
    assert(node);
    assert(get_branch_fill(node) == 1);
    int i = 0;
    for (; i < 1 << get_branch_bits(node); i++) {
        if (node->branches[i]) {
            return node->branches[i];
        }
    }
    return NULL;
}

static char *print_key(uint8_t * key, uint16_t prefix)
{
    static char outbuf[70];

    int bytes = prefix / 8;
    __hexdump(key, bytes, outbuf, 70);

    uint8_t bits = prefix % 8;
    if (bits > 0) {

        uint8_t byte = key[bytes] >> (8 - bits) << (8 - bits);
        __hexdump(&byte, 1, outbuf + bytes, 70 - bytes);
    }

    return outbuf;
}

static void update_shortest(struct prefix_trie_struct *trie,
                            struct prefix_trie_iter_node *inode);

static void *insert_prefix(struct prefix_trie_struct *trie,
                           struct prefix_trie_data *leaf,
                           struct prefix_trie_data *prefix, int freenew);
static void *remove_prefix(struct prefix_trie_struct *trie,
                           struct prefix_trie_data *dnode, uint8_t * key,
                           uint16_t prefix,
                           struct prefix_trie_data **oleaf, short *removed);

static void *remove_interstitial(struct prefix_trie_struct *trie,
                                 uint8_t offset, uint8_t level_bits,
                                 uint8_t * key, uint16_t prefix,
                                 struct prefix_trie_data **branches,
                                 struct prefix_trie_node *node, short *remd);
static void *insert_interstitial(struct prefix_trie_struct *trie,
                                 uint8_t offset, uint8_t level_bits,
                                 uint8_t * key, uint16_t prefix,
                                 void *data,
                                 struct prefix_trie_data **branches,
                                 struct prefix_trie_node *node,
                                 uint8_t * is_existing);

static void *search_alternates(struct prefix_trie_struct *trie,
                               struct prefix_trie_node *node,
                               struct prefix_trie_data *last_prefix,
                               uint8_t * key, uint16_t prefix,
                               uint8_t total_bits, uint8_t level_bits,
                               struct prefix_trie_data **branches,
                               uint8_t branch_index);

static void _prefix_trie_iter_init(struct prefix_trie_iter *iter,
                                   struct prefix_trie_struct *trie,
                                   int print_out);
static int _prefix_trie_iter_next(struct prefix_trie_iter *iter,
                                  uint8_t ** key, uint16_t * prefix,
                                  void **data, int print_out);

/*prefix's key/len is a conflicting prefix of leaf's key/len*/

static void *insert_prefix(struct prefix_trie_struct *trie,
                           struct prefix_trie_data *leaf,
                           struct prefix_trie_data *prefix, int freenew)
{
    assert(trie);
    assert(leaf);
    assert(prefix);

    void *odata = NULL;

    if (prefix->shortest < leaf->shortest) {
        leaf->shortest = prefix->shortest;
    }

    /*insert it in the right position of the prefix chain */
    while (leaf->prefix && leaf->prefix->len > prefix->len) {
        leaf = leaf->prefix;
        if (prefix->shortest < leaf->shortest) {
            leaf->shortest = prefix->shortest;
        }
    }

    if (leaf->prefix && leaf->prefix->len == prefix->len) {
        /*replace data/key */
        odata = leaf->prefix->data;
        leaf->prefix->data = prefix->data;
        leaf->prefix->key = prefix->key;
        /*responsible for destroying "new" leaf */
        //destroy_trie_node(trie, leaf);
        if (freenew) {
            destroy_trie_node(trie, prefix);
        }
    } else {
        /*insert into the prefix chain */

        if (leaf->prefix) {
            set_node_prefix(prefix, leaf->prefix);
        }
        set_node_prefix(leaf, prefix);
        //assert(prefix->ref_count == 1);

    }
    return odata;
}

/*for prefixes that fall into the level_bit bucket, replicate into all matching buckets*/
static void *insert_interstitial(struct prefix_trie_struct *trie,
                                 uint8_t offset, uint8_t level_bits,
                                 uint8_t * key, uint16_t prefix,
                                 void *data,
                                 struct prefix_trie_data **branches,
                                 struct prefix_trie_node *node,
                                 uint8_t * is_existing)
{

    if (level_bits <= prefix - offset) {
        LOG_ERR
            ("Replicated entries must fall within the level bits! %u >= %u",
             prefix, level_bits);
        return NULL;
    }
    //char buffer[128];
    /*replicate it */
    struct prefix_trie_data *newleaf =
        create_trie_data(trie, key, prefix, data, NULL);

    uint16_t branch_index = extract_bit_value(offset, prefix - offset,
                                              key) << (level_bits -
                                                       prefix + offset);

    //printf("inserting interstitial: prefix %u offset: %u level_bits: %u branch index: %u key: %s\n",prefix, offset, level_bits, branch_index, __hexdump(key, prefix / 8, buffer, 128));

    struct prefix_trie_data *next = branches[branch_index];
    void *odata = NULL;

    if (next) {
        /*an entry exists - check to see who is a prefix of whom */
        if (trie_get_type(next) == PREFIX_TRIE_TYPE_DATA) {
            if (next->len > prefix) {
                /*new is a prefix of the old */
                odata = insert_prefix(trie, next, newleaf, FALSE);
            } else if (next->len == prefix) {
                /*same guy */
                odata = next->data;
                next->data = data;
                next->key = key;
            } else {
                /*old is a prefix of the new */
                set_node_prefix(newleaf, next);
                //set_branch_child(trie, node, branches, branch_index + i, newleaf);
                set_branch_child(trie, node, branches, branch_index, newleaf);
            }
        } else {
            odata = insert_prefix(trie, next, newleaf, FALSE);
        }
        *is_existing = TRUE;
    } else {
        set_branch_child(trie, node, branches, branch_index, newleaf);
        *is_existing = FALSE;
    }

    if (odata) {
        /*free the data node since it's replacing an existing */
        destroy_trie_node(trie, newleaf);
    } else {
        assert(newleaf->ref_count > 0);
    }

    return odata;
}

static void *remove_prefix(struct prefix_trie_struct *trie,
                           struct prefix_trie_data *dnode, uint8_t * key,
                           uint16_t prefix,
                           struct prefix_trie_data **oleaf, short *removed)
{
    assert(dnode);
    assert(key);
    assert(removed);

    struct prefix_trie_data *rem;
    struct prefix_trie_data *orig = dnode;
    void *odata = NULL;

    if (dnode->prefix == NULL) {
        /*nothing to remove */
        *removed = FALSE;
        return odata;
    }

    int nshortest =
        trie_get_type(dnode) == PREFIX_TRIE_TYPE_DATA ? dnode->len : 0xFF;

    while (dnode->prefix) {
        //printf("checking prefix to remove:%s\n", print_trie_data(dnode->prefix));
        if (prefix == dnode->prefix->len) {
            *removed = TRUE;

            rem = dnode->prefix;
            //printf("removing matching prefix: %s\n", print_trie_data(rem));
            odata = rem->data;

            set_node_prefix(dnode, rem->prefix);

            if (oleaf) {
                *oleaf = rem;
            } else {
                assert(rem->ref_count == 0);
                destroy_trie_node(trie, rem);
            }

            /*reset shortest up the prefix chain */
            if (dnode->shortest == prefix) {
                dnode = orig;

                while (dnode) {
                    dnode->shortest = nshortest;
                    dnode = dnode->prefix;
                }

                /*for nodes, the new shortest is the shortest of the branches */
                if (trie_get_type(orig) != PREFIX_TRIE_TYPE_DATA) {
                    int i;
                    struct prefix_trie_node *node =
                        (struct prefix_trie_node *) orig;
                    for (i = 0; i < 1 << get_branch_bits(node); i++) {
                        if (node->branches[i]
                            && node->branches[i]->shortest < node->shortest) {
                            node->shortest = node->branches[i]->shortest;
                        }
                    }
                }
            }
            break;
        } else {
            nshortest = dnode->prefix->len;
        }
        dnode = dnode->prefix;
    }

    return odata;
}

static void *remove_interstitial(struct prefix_trie_struct *trie,
                                 uint8_t offset, uint8_t level_bits,
                                 uint8_t * key, uint16_t prefix,
                                 struct prefix_trie_data **branches,
                                 struct prefix_trie_node *node, short *remd)
{
    if (level_bits <= prefix - offset) {

        LOG_ERR
            ("Replicated entries must fall within the level bits! %u >= %u",
             prefix, level_bits);
        return NULL;
    }

    /*replicate it */
    //printf("removing interstitials! offset %u levelbits %u prefix %u\n", offset, level_bits, prefix);
    uint16_t branch_index = extract_bit_value(offset, prefix - offset,
                                              key) << (level_bits -
                                                       prefix + offset);
    struct prefix_trie_data *next = branches[branch_index];
    struct prefix_trie_data *oldleaf;
    void *odata = NULL;

    if (next) {
        if (trie_get_type(next) == PREFIX_TRIE_TYPE_DATA) {
            if (next->len > prefix) {
                /*key is a prefix of the existing */
                odata = remove_prefix(trie, next, key, prefix, &oldleaf, remd);
            } else if (next->len == prefix) {
                /*same guy */
                odata = next->data;
                next->data = NULL;
                oldleaf = next;
                set_branch_child(trie, node, branches, branch_index, NULL);
                *remd = TRUE;
            } else {
                /*otherwise, the entry is missing! */
                *remd = FALSE;
                return NULL;
            }
        }
    }

    /*reset shortest @ this node */
    if (prefix == node->shortest && *remd) {
        node->shortest = 0xFF;
        int i = 0;
        for (i = 0; i < 1 << get_branch_bits(node); i++) {
            if (node->branches[i]
                && node->branches[i]->shortest < node->shortest) {
                node->shortest = node->branches[i]->shortest;
            }
        }
    }

    if (oldleaf) {
        destroy_trie_node(trie, oldleaf);
    }

    return odata;
}

void *prefix_trie_insert(struct prefix_trie_struct *trie, uint8_t * key,
                         uint16_t prefix, void *data)
{
    assert(trie);

    /* insert = replace, although we may want to signal an error on replace in certain
     * cases */

    void *odata = NULL;

    if (prefix == 0) {
        /*replace the default value */
        //printf("replacing the default value\n");
        odata = trie->def_value;
        trie->def_value = data;
        trie->shortest = 0;
        if (!odata) {
            trie->count++;
        }
        return odata;
    }

    if (key == NULL) {
        return NULL;
    }

    /* branch index of the current node */
    uint8_t branch_index = 0;
    uint8_t prev_branch_index = 0;
    uint8_t prev2_branch_index = 0;

    /*tracks the current bit offset = #bits traversed */
    uint8_t total_bits = 0;

    /* length of the common prefix between the key and the current
     * node starting from the total_bits offset
     */
    uint8_t common_prefix = 0;

    /* # checks whether the node is full = skip=0 and one child on either side of the MSB divide */
    uint8_t node_full = 0;
    uint8_t is_data = 0;

    /* branching bits per node traversal */
    uint8_t level_bits = PREFIX_TRIE_ROOT_BIT;

    /*next node to visit - can be either data or internal */
    struct prefix_trie_data *next = NULL;
    struct prefix_trie_node *node = NULL;

    /* track up to 2 previous nodes in the path
     * prev = to check for doubling: either doubling prev, or the split node
     * prev2 = to check for doubling: if prev becomes full on insert
     */
    struct prefix_trie_node *prev3 = NULL;
    struct prefix_trie_node *prev2 = NULL;
    struct prefix_trie_node *prev = NULL;

    /* for creating the new leaf data node */
    struct prefix_trie_data *newleaf = NULL;

    int level = 0;
    /*key length at the current node */
    uint16_t node_prefix = 0;
    /*bits remaining to be traversed in the key length */
    uint16_t bits_left = prefix;

    /* branches used to handle the root branch along with node branches
     * track up to 2 previous branches for double/split
     */
    struct prefix_trie_data **branches = trie->root_branch;
    struct prefix_trie_data **prev_branches = NULL;
    struct prefix_trie_data **prev2_branches = NULL;

    //char buffer[128];
    //printf("INSERTING with prefix: %u key %s\n", prefix, __hexdump(key, prefix / 8 + (prefix % 8 > 0 ? 1 : 0), buffer, 128));

    /*shortest must be > 0 */
    if (prefix < trie->shortest) {
        /* we can always update the trie shortest prefix up front as long as the prefix > 0 and the key is valid */
        trie->shortest = prefix;
    }

    /* traverse the entire prefix key span to find the longest match and insert point */
    while (bits_left >= level_bits) {

        /* track up to 3 branch indices to maintain child pointers on split/doubling */
        prev2_branch_index = prev_branch_index;
        prev_branch_index = branch_index;
        branch_index = extract_bit_value(total_bits, level_bits, key);

        //printf("next branch index: %u total bits: %u level bits %u\n", branch_index, total_bits, level_bits);

        /* track up to 3 consecutive nodes in the path for doubling and maintaining child pointers */
        prev3 = prev2;
        prev2 = prev;
        prev = node;
        next = branches[branch_index];

        /*consume the bits on the current branch traversal */
        total_bits += level_bits;
        bits_left -= level_bits;

        if (next) {
            /*check to see if the node is data or internal */
            is_data = trie_get_type(next) == PREFIX_TRIE_TYPE_DATA;

            if (is_data) {
                /*find the longest common prefix */
                //printf("matching against data: %s\n", print_trie_data(next));
                node_prefix = next->len;

                if (next->len < total_bits) {
                    /*interstitial! */
                    total_bits = next->len;
                    bits_left = prefix - next->len;
                }
            } else {
                /* follow the node path */
                node = (struct prefix_trie_node *) next;
                node_prefix = total_bits + node->skip;
                //printf("following the node path with: %s\n", print_trie_node(node, total_bits));

            }

            common_prefix =
                find_longest_common_prefix(key, next->key, total_bits,
                                           (prefix >
                                            node_prefix ? node_prefix -
                                            total_bits : bits_left));

            //printf("common prefix between key and node/data: %u total_bits %u len %u bits_left %u\n", common_prefix, total_bits, node_prefix, bits_left);
            //printf("original key: %s\n", __hexdump(next->key, node_prefix / 8 + (node_prefix % 8 > 0 ? 1 : 0), buffer, 128));

            if (common_prefix + total_bits == prefix) {
                if (prefix == node_prefix) {
                    if (is_data) {
                        //printf("replacing the original key/value with prefix: %u %s\n", prefix, __hexdump(key, prefix / 8 + (prefix % 8 > 0 ? 1 : 0), buffer, 128));
                        odata = next->data;
                        next->data = data;
                        next->key = key;
                        goto out;
                    }
                }

                newleaf = create_trie_data(trie, key, prefix, data, NULL);
                odata = insert_prefix(trie, next, newleaf, TRUE);

                //printf("the key is a prefix of the original: %u < %u\n", prefix, node_prefix);

                goto out;
            }

            /*check to see if one is a prefix of another */
            if (common_prefix + total_bits == node_prefix) {
                /*the old value should become a prefix of the new */
                if (is_data) {
                    //printf("the original key/value is a prefix of the new: %u < %u\n", node_prefix, prefix);
                    newleaf = create_trie_data(trie, key, prefix, data, next);
                    set_branch_child(trie, prev, branches, branch_index,
                                     newleaf);
                    assert(next->ref_count == 1);
                    goto out;
                } else {
                    /*continue on the node path */
                    //printf("continuing on the node path\n");
                    level++;
                    if (prefix < node->shortest) {
                        node->shortest = prefix;
                    }
                    total_bits += node->skip;
                    bits_left -= node->skip;
                    level_bits = get_branch_bits(node);
                    prev2_branches = prev_branches;
                    prev_branches = branches;
                    branches =
                        (struct prefix_trie_data **) (((uint8_t *) node) +
                                                      sizeof(*node));
                    continue;
                }
            }

            /*create the new node and insert - common_prefix < node_prefix */
            if (prev && common_prefix == 0) {
                /*check to see if the insertion would cause the parent to double since the parent will inc full */
                /*we know that the split node will be full - binary w/ 2 children */
                inc_branch_full(prev);
                //printf("inserting into existing node - common prefix == 0 total_len: %u\n", total_bits);

                if (should_double(trie, prev)) {
                    //printf("doubling the node! %u %u %u\n", get_branch_bits(prev), get_branch_fill(prev), get_branch_full(prev));

                    /*don't free prev! */
                    node = double_node(trie, prev, total_bits - level_bits);

                    /* reset the (grand)parent's child pointer to the new parent node */
                    set_branch_child(trie, prev2, prev_branches,
                                     prev_branch_index,
                                     (struct prefix_trie_data *) node);

                    /*insert the new leaf node */
                    newleaf = create_trie_data(trie, key, prefix, data, NULL);

                    /*need to get the bits "prior" to traversing the node since we're replacing
                     * the node
                     */

                    branch_index =
                        get_branch_index(newleaf, total_bits - level_bits,
                                         get_branch_bits(node));

                    //printf("inserting into new, doubled node: %u new fill %u %s\n", branch_index, get_branch_fill(node), print_trie_node(node, total_bits));

                    set_branch_child(trie, node, node->branches,
                                     branch_index, newleaf);

                    //printf("leafnode: %s\n", print_trie_data(newleaf));
                    //printf("destroying old prev: %s\n", print_trie_node(prev, total_bits- level_bits));
                    destroy_trie_node(trie, (struct prefix_trie_data *) prev);

                    assert(newleaf->ref_count > 0);
                    goto out;
                }

            }

            node =
                split_path(trie, total_bits, common_prefix, next, key,
                           prefix, data);
            //printf("splitting the data node path: branch index %u bits %u fill %u full%u %s\n",branch_index, get_branch_bits(node), get_branch_fill(node),get_branch_full(node), print_trie_node(node, total_bits));
            assert(trie_get_type((struct prefix_trie_data *) node) !=
                   PREFIX_TRIE_TYPE_DATA);
            set_branch_child(trie, prev, branches, branch_index,
                             (struct prefix_trie_data *) node);

            goto out;
        } else {
            /*null slot - insert and see if we need to expand */
            //newleaf = create_trie_data(trie, key, prefix, data, (prev ? prev->prefix : NULL));
            newleaf = create_trie_data(trie, key, prefix, data, NULL);

            if (prev) {
                node_full = is_node_full((struct prefix_trie_data *) prev);
            }

            set_branch_child(trie, prev, branches, branch_index, newleaf);

            if (prev) {
                if (should_double(trie, prev)) {
                    /*doubling does not affect full status */
                    node = double_node(trie, prev, total_bits - level_bits);
                    /*prev branches should be non-null */
                    set_branch_child(trie, prev2, prev_branches,
                                     prev_branch_index,
                                     (struct prefix_trie_data *) node);
                    destroy_trie_node(trie, (struct prefix_trie_data *) prev);
                } else if (prev2 && is_node_full((struct prefix_trie_data *)
                                                 prev) && !node_full) {
                    inc_branch_full(prev2);

                    if (should_double(trie, prev2)) {
                        print_trie_node(prev2,
                                        total_bits - level_bits -
                                        prev->skip - get_branch_bits(prev2));

                        node =
                            double_node(trie, prev2,
                                        total_bits - level_bits -
                                        prev->skip - get_branch_bits(prev2));
                        set_branch_child(trie, prev3, prev2_branches,
                                         prev2_branch_index,
                                         (struct prefix_trie_data *) node);
                        destroy_trie_node(trie, (struct prefix_trie_data *)
                                          prev2);
                    }
                }
            }
            goto out;
        }
    }

    /*running out of bits (into the middle of a node's branch bits) occurs for the most recent node encountered */
    if (node) {
        node_full = is_node_full((struct prefix_trie_data *) node);
    }

    odata =
        insert_interstitial(trie, total_bits, level_bits, key, prefix,
                            data, branches, node, &is_data);

    /*check for doubling */
    if (!is_data && node) {
        if (should_double(trie, node)) {
            /*doubling does not affect full status */
            prev2 = double_node(trie, node, total_bits);
            /*prev branches should be non-null - note that the node here is prev vs. prev2 since we haven't traversed and updated prev2=prev */
            //printf("setting parent (prev) %s branch ind: %u\n", print_trie_node(prev, total_bits - node->skip - get_branch_bits(prev)), branch_index);
            set_branch_child(trie, prev, prev_branches, branch_index,
                             (struct prefix_trie_data *) prev2);
            destroy_trie_node(trie, (struct prefix_trie_data *) node);
        } else if (prev && is_node_full((struct prefix_trie_data *) node)
                   && !node_full) {
            inc_branch_full(prev);

            if (should_double(trie, prev)) {
                print_trie_node(prev,
                                total_bits - node->skip -
                                get_branch_bits(prev));

                prev3 =
                    double_node(trie, prev,
                                total_bits - node->skip -
                                get_branch_bits(prev));

                set_branch_child(trie, prev2, prev2_branches,
                                 prev_branch_index,
                                 (struct prefix_trie_data *) prev3);
                destroy_trie_node(trie, (struct prefix_trie_data *) prev);
            }
        }
    }

 out:if (level > trie->max_depth) {
        trie->max_depth = level;
    }
    /* TODO valid test for non-prefix inserts, since insert_prefix may replace an existing and destroy/free the newleaf */
    //    if(newleaf) {
    //        assert(newleaf->ref_count > 0);
    //    }
    return odata;
}

int prefix_trie_initialize(struct prefix_trie_struct *trie, size_t keylen,
                           float fillfactor)
{
    assert(trie);
    /*assume the trie has been bzero'd */
    trie->key_len = keylen;
    /* technically there can be one more level if keylen is exactly divisible
     * but anything more than max_depth means a leaf (value)
     */
    trie->fill_factor = fillfactor;
    trie->shortest = 0xFFFF;
    return 0;
}

int prefix_trie_finalize(struct prefix_trie_struct *trie)
{
    /* march through and destroy any remaining nodes - the real question is what to do with values */
    assert(trie);

    if (trie->count > 0) {
        struct prefix_trie_iter iter;
        prefix_trie_iter_init(&iter, trie);

        while (prefix_trie_iter_remove(&iter)) {

        }

        prefix_trie_iter_destroy(&iter);
    }

    trie->max_depth = 0;
    assert(trie->branch_fill == 0);
    assert(trie->count == 0);
    assert(trie->node_count == 0);

    return 0;
}

void *prefix_trie_remove(struct prefix_trie_struct *trie, uint8_t * key,
                         uint16_t prefix)
{
    assert(trie);

    void *odata = NULL;

    /*sanity check the values ? */
    /*child branch index - track up to 2 path nodes */
    uint8_t branch_index = 0;
    uint8_t prev_branch_index = 0;

    uint8_t total_bits = 0;
    uint8_t level_bits = PREFIX_TRIE_ROOT_BIT;

    struct prefix_trie_data *next = NULL;

    struct prefix_trie_data *temp = NULL;
    struct prefix_trie_node *node = NULL;

    /*track up to 2 path nodes for halving */
    struct prefix_trie_node *prev = NULL;
    struct prefix_trie_node *prev2 = NULL;

    uint16_t node_prefix = 0;
    uint16_t bits_left = prefix;
    short is_data = 0;
    uint16_t common_prefix = 0;

    short is_full = FALSE;
    short removed = FALSE;
    /*branches used to handle the root case */
    struct prefix_trie_data **branches = trie->root_branch;
    struct prefix_trie_data **prev_branches = NULL;

    uint16_t shortest = trie->shortest;
    struct prefix_trie_iter_node *track = NULL;

    int i = 0;
    //char buffer[128];

    printf("REMOVING prefix: %u key %s\n", prefix, print_key(key, prefix));

    if (prefix == 0) {
        /*remove the default value */
        odata = trie->def_value;
        trie->def_value = NULL;
        if (odata) {
            trie->count--;
            shortest = 0xFF;
            for (i = 0; i < PREFIX_TRIE_ROOT_BRANCH; i++) {
                if (trie->root_branch[i]
                    && trie->root_branch[i]->shortest < shortest) {
                    shortest = trie->root_branch[i]->shortest;
                }
            }
            trie->shortest = shortest;
        }
        return odata;
    }

    while (bits_left >= level_bits) {
        if (prefix == shortest) {
            /*track the level */
            //printf("Tracking shortest: %u at node: %s\n", shortest, node ? print_trie_node(node, total_bits) : "root");
            track =
                create_iter_node(total_bits, branches, branch_index, 0,
                                 node, track);
        } else if (prefix < shortest) {
            goto out;
        }

        prev_branch_index = branch_index;
        branch_index = extract_bit_value(total_bits, level_bits, key);
        printf("next branch index: %u\n", branch_index);

        prev2 = prev;
        prev = node;
        next = branches[branch_index];

        total_bits += level_bits;
        bits_left -= level_bits;
        shortest = next->shortest;

        if (next) {
            /*check to see if the node is data or internal */
            is_data = trie_get_type(next) == PREFIX_TRIE_TYPE_DATA;
            if (is_data) {
                /* we've hit a leaf */
                /* note that the search key's prefix must be >= leaf key,
                 * otherwise the leaf key would be matching on "phantom" bits
                 */
                //printf("removing from a leaf node: %s\n", print_trie_data(next));
                node_prefix = next->len;

            } else {
                /* follow the path - may not need to key-compare again here, but it would
                 * fail-fast and avoid unnecessary trie traversals on a full path-compressed
                 * leaf lookup
                 */
                node = (struct prefix_trie_node *) next;
                printf("following a node path: %s\n",
                       print_trie_node(node, total_bits));
                node_prefix = total_bits + node->skip;
            }

            if (prefix == node_prefix && is_data) {
                /*check the leaf node for equality */
                if (is_bitstring_equal(key, next->key, total_bits, bits_left)) {
                    //printf("removing a data node\n");
                    odata = next->data;
                    next->data = NULL;

                    update_shortest(trie, track);

                    /*if a prefix is fully unlinked (refcount == 0), then it replaces the data node */
                    temp = next->prefix;
                    if (set_node_prefix(next, NULL)) {
                        //printf("replacing leaf node with prefix: %s\n", print_trie_data(temp));
                        assert(temp->ref_count == 0);
                        set_branch_child(trie, prev, branches,
                                         branch_index, temp);
                        assert(temp->ref_count == 1);
                    } else {
                        is_full =
                            is_node_full((struct prefix_trie_data *) prev);
                        set_branch_child(trie, prev, branches,
                                         branch_index, NULL);

                        if (prev) {

                            if (get_branch_fill(prev) == 1) {
                                /*the node has only 1 branch,
                                 * so it must be replaced with its child*/
                                /*reduce the parent node - note that the prefix refcount will at least be
                                 * 1 since the other branch will still reference it */

                                for (i = 0; i < 1 << get_branch_bits(prev); i++) {
                                    if (prev->branches[i]) {
                                        printf
                                            ("replacing parent node with single remaining child at %u: %s %s\n",
                                             prev_branch_index,
                                             print_trie_node(prev,
                                                             total_bits -
                                                             level_bits),
                                             print_trie_data(prev->branches
                                                             [i]));
                                        if (prev2) {
                                            printf
                                                ("grandparent before: %s\n",
                                                 print_trie_node(prev2,
                                                                 total_bits
                                                                 -
                                                                 level_bits
                                                                 -
                                                                 prev->skip
                                                                 -
                                                                 get_branch_bits
                                                                 (prev2)));
                                        }

                                        set_branch_child(trie, prev2,
                                                         prev_branches,
                                                         prev_branch_index,
                                                         prev->branches[i]);

                                        if (prev2) {
                                            printf
                                                ("grandparent after: %s\n",
                                                 print_trie_node(prev2,
                                                                 total_bits
                                                                 -
                                                                 level_bits
                                                                 -
                                                                 prev->skip
                                                                 -
                                                                 get_branch_bits
                                                                 (prev2)));
                                        }

                                        /*if the node had a prefix, then the child must inherit it */
                                        if (prev->prefix) {
                                            /*insert vs. last_prefix_of to ensure that shortest is updated all the way up */
                                            insert_prefix(trie,
                                                          prev->branches
                                                          [i],
                                                          prev->prefix, FALSE);
                                        }

                                        /*if the child is a node, increment the skip bits by the number of bits in the parent node's branch */
                                        if (trie_get_type(prev->branches[i])
                                            != PREFIX_TRIE_TYPE_DATA) {
                                            //printf("incremented skip: %s\n", print_trie_node(((struct prefix_trie_node*) prev->branches[i]), total_bits));
                                            ((struct prefix_trie_node *)
                                             prev->branches[i])->skip +=
                                                get_branch_bits(prev) +
                                                prev->skip;
                                        }
                                        break;
                                    }
                                }

                                if (prev2 && is_full) {
                                    /*fill doesn't change, just full */
                                    assert(get_branch_full(prev2) > 0);
                                    dec_branch_full(prev2);
                                    printf
                                        ("singleton leaf replace full change prev2: %s\n",
                                         print_trie_node(prev2,
                                                         total_bits -
                                                         level_bits -
                                                         prev->skip -
                                                         get_branch_bits
                                                         (prev2)));
                                }

                                destroy_trie_node(trie,
                                                  (struct prefix_trie_data
                                                   *) prev);
                            } else if (should_halve(trie, prev)) {
                                //printf("halving a node: %s\n", print_trie_node(prev, total_bits));
                                temp = halve_node(trie, prev);
                                set_branch_child(trie, prev2,
                                                 prev_branches,
                                                 prev_branch_index, temp);
                                destroy_trie_node(trie,
                                                  (struct prefix_trie_data
                                                   *) prev);

                                /*full */
                                if (prev2) {
                                    if (is_full) {
                                        if (!is_node_full(temp)) {
                                            assert(get_branch_full(prev2) > 0);
                                            dec_branch_full(prev2);
                                        }
                                    } else if (is_node_full(temp)) {
                                        assert(get_branch_full(prev2) > 0);
                                        inc_branch_full(prev2);
                                    }
                                    printf
                                        ("halved node possible full change prev2: %s\n",
                                         print_trie_node(prev2,
                                                         total_bits -
                                                         level_bits -
                                                         prev->skip -
                                                         get_branch_bits
                                                         (prev2)));
                                }
                            } else if (prev2 && is_full
                                       &&
                                       !is_node_full((struct prefix_trie_data *)
                                                     prev)) {
                                /*full status of prev changed - update its parent */
                                assert(get_branch_full(prev2) > 0);
                                dec_branch_full(prev2);
                                printf
                                    ("regular remove full change prev2: %s\n",
                                     print_trie_node(prev2,
                                                     total_bits -
                                                     level_bits -
                                                     prev->skip -
                                                     get_branch_bits(prev2)));
                            }
                        }
                    }

                    destroy_trie_node(trie, next);
                    goto out;

                }
                goto out;
            }

            if (node_prefix >= prefix) {
                /*search the prefix tree */
                common_prefix =
                    find_longest_common_prefix(key, next->key, 0, node_prefix);
                //printf("searching the prefix tree\n");
                if (common_prefix < prefix) {
                    //printf("no matching prefix length found!\n");
                    goto out;
                }

                odata = remove_prefix(trie, next, key, prefix, NULL, &removed);

                if (removed) {
                    update_shortest(trie, track);
                }
                goto out;
            }

            if (is_data) {
                /* prefix > data's node_prefix */
                assert(prefix > node_prefix);
                goto out;
            }

            /* continue on the node path only if the prefix/skip matches */
            if (is_bitstring_equal
                (key, next->key, total_bits, node_prefix - total_bits)) {
                //printf("continuing on the node path\n");
                total_bits += node->skip;
                bits_left -= node->skip;
                /*continue */
                level_bits = get_branch_bits(node);
                prev_branches = branches;
                branches =
                    (struct prefix_trie_data **) (((uint8_t *) node) +
                                                  sizeof(*node));
            } else {
                goto out;
            }

        } else {
            goto out;
        }
    }

    is_full = is_node_full(next);

    odata
        =
        remove_interstitial(trie, total_bits, level_bits, key, prefix,
                            branches, node, &removed);

    if (removed) {
        update_shortest(trie, track);

        if (node) {
            if (get_branch_fill(node) == 1) {
                /*the node has only 1 branch,
                 * so it must be replaced with its child*/
                /*reduce the parent node - note that the prefix refcount will at least be
                 * 1 since the other branch will still reference it */

                for (i = 0; i < 1 << get_branch_bits(node); i++) {
                    if (node->branches[i]) {
                        set_branch_child(trie, prev, prev_branches,
                                         branch_index, node->branches[i]);

                        /*if the node had a prefix, then the child must inherit it */
                        if (node->prefix) {
                            //set_node_prefix(last_prefix_of(node->branches[i], 0), node->prefix);
                            insert_prefix(trie, node->branches[i],
                                          node->prefix, FALSE);
                        }

                        /*if the child is a node, increment the skip bits by the number of bits in the parent node's branch */
                        if (trie_get_type(node->branches[i]) !=
                            PREFIX_TRIE_TYPE_DATA) {
                            ((struct prefix_trie_node *)
                             node->branches[i])->skip +=
                                get_branch_bits(node) + node->skip;
                        }

                        break;
                    }
                }

                if (prev && is_full) {
                    /*fill doesn't change, just full */
                    assert(get_branch_full(prev) > 0);
                    dec_branch_full(prev);
                    printf
                        ("interstitial singleton replace full change prev: %s\n",
                         print_trie_node(prev, total_bits));
                }

                destroy_trie_node(trie, (struct prefix_trie_data *) node);
            } else if (should_halve(trie, node)) {
                //printf("halving a node: %s\n", print_trie_node(node, total_bits));
                temp = halve_node(trie, node);
                set_branch_child(trie, prev, prev_branches, branch_index, temp);
                destroy_trie_node(trie, (struct prefix_trie_data *) node);

                /*full */
                if (prev) {
                    if (is_full) {
                        if (!is_node_full(temp)) {
                            assert(get_branch_full(prev) > 0);
                            dec_branch_full(prev);
                        }
                    } else if (is_node_full(temp)) {
                        assert(get_branch_full(prev) > 0);
                        inc_branch_full(prev);
                    }
                    printf("halved node possible full change prev: %s\n",
                           print_trie_node(prev, total_bits));
                }
            } else if (prev && is_full
                       && !is_node_full((struct prefix_trie_data *) node)) {
                /*full status of prev changed - update its parent */
                assert(get_branch_full(prev) > 0);
                dec_branch_full(prev);
                printf("regular remove full change prev: %s\n",
                       print_trie_node(prev, total_bits));
            }
        }
    }

 out:destroy_iter_node_list(track);
    return odata;
}

static void *search_alternates(struct prefix_trie_struct *trie,
                               struct prefix_trie_node *node,
                               struct prefix_trie_data *last_prefix,
                               uint8_t * key, uint16_t prefix,
                               uint8_t total_bits, uint8_t level_bits,
                               struct prefix_trie_data **branches,
                               uint8_t branch_index)
{

    uint8_t found = FALSE;
    uint8_t bit_check = 0;
    void *data = NULL;
    struct prefix_trie_data *next;

    /*if the branch node (leaf or node) has prefixes, and there is a suitable one (<= key length)
     *then search.
     */
    if (branches[branch_index]
        && branches[branch_index]->shortest <= prefix) {
        //printf("searching prefix tree!\n");
        data =
            search_prefix(branches[branch_index]->prefix, key, prefix,
                          total_bits, &found);
    }

    if (!found) {
        //printf("searching interstitials? total bits: %u level bits: %u shortest %u\n", total_bits,level_bits, (node ? node->shortest : trie->shortest));

        //node->shortest > total_bits &&
        if (level_bits > 1
            && ((node && node->shortest < total_bits + level_bits)
                || (!node && trie->shortest < PREFIX_TRIE_ROOT_BIT))) {
            /*search for interstitial prefixes */
            for (bit_check = 1; bit_check < level_bits; bit_check++) {
                branch_index = branch_index >> bit_check << bit_check;

                next = branches[branch_index];
                //printf("searching interstitial branch: %u\n", branch_index);
                if (next) {
                    //printf("checking interstitial node: %s\n", print_trie_data(next));
                    if (trie_get_type(next) == PREFIX_TRIE_TYPE_DATA) {
                        if (total_bits + (level_bits - bit_check) >=
                            next->len && next->len <= prefix) {
                            return next->data;
                        }
                        if (total_bits + (level_bits - bit_check) >=
                            next->shortest && next->shortest <= prefix) {
                            data =
                                search_prefix(next->prefix, key, prefix,
                                              total_bits, &found);
                            assert(found);
                            break;
                        }
                    } else if (next->shortest <= prefix) {
                        data =
                            search_prefix(next->prefix, key, prefix,
                                          total_bits, &found);
                        assert(found);
                        break;
                    }
                }
            }
        }
    }

    if (!found && last_prefix && last_prefix->shortest <= prefix) {
        /*back track in the search */
        //printf("returning back tracking last prefix: %s!\n", print_trie_data(last_prefix));
        data =
            search_prefix(last_prefix, key, prefix, last_prefix->shortest,
                          &found);
        //data = last_prefix->data;

    }

    if (!found) {
        data = trie->def_value;
    }

    return data;
}

void *prefix_trie_find(struct prefix_trie_struct *trie, uint8_t * key,
                       uint16_t prefix)
{
    assert(trie);

    if (key == NULL || prefix < trie->shortest) {
        return NULL;
    }

    /*sanity check the values ? */
    uint8_t branch_index = 0;
    uint8_t total_bits = 0;
    void *data = NULL;

    struct prefix_trie_data *next = NULL;
    struct prefix_trie_node *node = NULL;
    struct prefix_trie_node *prev = NULL;

    uint8_t level_bits = PREFIX_TRIE_ROOT_BIT;
    //uint8_t shortest = trie->shortest;
    /*TODO this really shouldn't need to be 16 bits */
    uint16_t bits_left = prefix;

    struct prefix_trie_data *last_prefix = NULL;

    struct prefix_trie_data **branches = trie->root_branch;

    //uint8_t found = FALSE;
    //char buffer[128];
    //printf("FINDING prefix: %u key %s\n", prefix, __hexdump(key, prefix / 8 + (prefix % 8 > 0 ? 1 : 0), buffer, 128));

    if (prefix == 0) {
        //printf("default match\n");
        return trie->def_value;
    }

    while (bits_left >= level_bits) {

        branch_index = extract_bit_value(total_bits, level_bits, key);
        prev = node;
        next = branches[branch_index];

        //printf("branch index: %u\n", branch_index);
        total_bits += level_bits;
        bits_left += level_bits;

        if (next) {

            /*check to see if the node is data or internal */
            if (trie_get_type(next) == PREFIX_TRIE_TYPE_DATA) {
                /* we've hit a leaf */
                /* note that the search key's prefix must be >= leaf key,
                 * otherwise the leaf key would be matching on "phantom" bits
                 */

                //printf("comparing to key at bit %u to %u: %s\n", total_bits, (prefix > next->len ? next->len - total_bits : bits_left), __hexdump(next->key, next->len / 8 + (next->len % 8 > 0 ? 1 : 0), buffer, 128));
                if (prefix >= next->len
                    && is_bitstring_equal(key, next->key, total_bits,
                                          (prefix >
                                           next->len ? next->len -
                                           total_bits : prefix -
                                           total_bits)) == TRUE) {

                    return next->data;
                }
                /*search the prefix tree */
                //printf("search the data (alternate) prefix tree\n");

                data =
                    search_alternates(trie, prev, last_prefix, key, prefix,
                                      total_bits - level_bits, level_bits,
                                      branches, branch_index);

                return data;
            }

            /* follow the path - may not need to key-compare again here, but it would
             * fail-fast and avoid unnecessary trie traversals on a full path-compressed
             * leaf lookup
             */
            node = (struct prefix_trie_node *) next;
            //printf("following the node path: %s\n", print_trie_node(node, total_bits));

            if (bits_left <= node->skip || prefix < node->shortest
                || !is_bitstring_equal(key, next->key, total_bits,
                                       (bits_left >
                                        node->skip ? node->skip : bits_left))) {
                //printf("searching prefix: bits left %u node skip: %u total bits: %u\n", bits_left, node->skip, total_bits);

                data =
                    search_alternates(trie, prev, last_prefix, key, prefix,
                                      total_bits - level_bits, level_bits,
                                      branches, branch_index);

                return data;
            }

            if (node->prefix) {
                last_prefix = node->prefix;
            }

            total_bits += node->skip;
            bits_left -= node->skip;
            //shortest = next->shortest;
            /*continue */
            level_bits = get_branch_bits(node);
            branches =
                (struct prefix_trie_data **) (((uint8_t *) node) +
                                              sizeof(*node));
        } else {
            //printf("no branch found\n");
            return search_alternates(trie, prev, last_prefix, key, prefix,
                                     total_bits - level_bits, level_bits,
                                     branches, branch_index);
        }
    }

    branch_index =
        extract_bit_value(total_bits, bits_left,
                          key) << (level_bits - bits_left);
    //printf("we're somewhere in the middle - find the right branch value: %i\n", branch_index);

    return search_alternates(trie, node, last_prefix, key, prefix,
                             total_bits, level_bits, branches, branch_index);

}

void *prefix_trie_find_exact(struct prefix_trie_struct *trie,
                             uint8_t * key, uint16_t prefix)
{
    assert(trie);

    if (key == NULL) {
        return NULL;
    }

    /*sanity check the values ? */
    uint8_t branch_index = 0;
    uint8_t total_bits = 0;

    struct prefix_trie_data *next = NULL;
    struct prefix_trie_node *node = NULL;

    uint8_t level_bits = PREFIX_TRIE_ROOT_BIT;
    uint8_t shortest = trie->shortest;
    uint8_t bits_left = prefix;

    struct prefix_trie_data **branches = trie->root_branch;

    uint8_t found = FALSE;
    //char buffer[128];
    //printf("FINDING prefix: %u key %s\n", prefix, __hexdump(key, prefix / 8 + (prefix % 8 > 0 ? 1: 0), buffer, 128));

    if (prefix == 0) {
        //printf("default match\n");
        return trie->def_value;
    }

    while (bits_left >= level_bits) {
        if (prefix < shortest) {
            return NULL;
        }

        branch_index = extract_bit_value(total_bits, level_bits, key);
        next = branches[branch_index];

        //printf("branch index: %u\n", branch_index);
        total_bits += level_bits;
        bits_left -= level_bits;

        if (next) {
            /*check to see if the node is data or internal */
            if (trie_get_type(next) == PREFIX_TRIE_TYPE_DATA) {
                /* we've hit a leaf */
                /* note that the search key's prefix must be >= leaf key,
                 * otherwise the leaf key would be matching on "phantom" bits
                 */

                //printf("comparing to key at bit %u to %u: %s\n", total_bits, (prefix > next->len ? next->len - total_bits : bits_left),__hexdump(next->key, next->len / 8 + (next->len % 8 > 0 ? 1 : 0), buffer,128));
                //printf("prefix key: %s\n", __hexdump(key, prefix / 8 + (prefix % 8 > 0 ? 1 : 0),buffer, 128));
                if (prefix == next->len
                    && is_bitstring_equal(key, next->key, total_bits,
                                          (prefix >
                                           next->len ? next->len -
                                           total_bits : bits_left)) == TRUE) {
                    return next->data;
                }
                /*search the prefix tree */
                //printf("search the data prefix tree\n");
                return search_prefix_exact(next->prefix, key, prefix,
                                           total_bits, &found);

            }

            /* follow the path - may not need to key-compare again here, but it would
             * fail-fast and avoid unnecessary trie traversals on a full path-compressed
             * leaf lookup
             */
            node = (struct prefix_trie_node *) next;
            //printf("following the node path: %s\n", print_trie_node(node, total_bits));

            if (prefix - total_bits <= node->skip
                || !is_bitstring_equal(key, next->key, total_bits,
                                       (prefix - total_bits >
                                        node->skip ? node->skip : bits_left))) {
                //printf("searching prefix: bits left %u node skip: %u total bits: %u\n", bits_left,node->skip, total_bits);
                return search_prefix_exact(next->prefix, key, prefix,
                                           total_bits, &found);
            }

            total_bits += node->skip;
            bits_left -= node->skip;
            /*continue */
            level_bits = get_branch_bits(node);
            branches =
                (struct prefix_trie_data **) (((uint8_t *) node) +
                                              sizeof(*node));
            shortest = next->shortest;
        } else {
            return NULL;
        }
    }

    branch_index =
        extract_bit_value(total_bits, bits_left,
                          key) << (level_bits - bits_left);

    printf
        ("we're somewhere in the middle - find the right branch value: %i\n",
         branch_index);
    next = branches[branch_index];

    if (next) {
        /*we could be a prefix */
        if (trie_get_type(next) == PREFIX_TRIE_TYPE_DATA) {
            if (next->len > prefix) {
                return search_prefix_exact(next->prefix, key, prefix,
                                           total_bits, &found);
            }
            if (next->len < prefix) {
                return NULL;
            }
            /*next->len cannot be < prefix */
            return next->data;
        }
        /*it's a node - search the prefix */
        return search_prefix_exact(next->prefix, key, prefix, total_bits,
                                   &found);
    }

    return NULL;
}

int prefix_trie_has_key(struct prefix_trie_struct *trie, uint8_t * key,
                        uint16_t prefix)
{
    assert(trie);

    if (key == NULL) {
        return FALSE;
    }

    /*sanity check the values ? */
    uint8_t branch_index = 0;
    uint8_t total_bits = 0;
    uint8_t bits_left = prefix;

    struct prefix_trie_data *next = NULL;
    struct prefix_trie_node *node = NULL;

    uint8_t level_bits = PREFIX_TRIE_ROOT_BIT;
    uint8_t shortest = trie->shortest;

    struct prefix_trie_data **branches = trie->root_branch;

    uint8_t found = FALSE;
    //char buffer[128];
    //printf("FINDING prefix: %u key %s\n", prefix, __hexdump(key, prefix / 8 + (prefix % 8 > 0 ? 1 : 0), buffer, 128));

    if (prefix == 0) {
        //printf("default match\n");
        return trie->def_value != NULL;
    }

    while (prefix - total_bits >= level_bits) {
        if (prefix < shortest) {
            return FALSE;
        }

        branch_index = extract_bit_value(total_bits, level_bits, key);
        next = branches[branch_index];

        //printf("branch index: %u\n", branch_index);
        total_bits += level_bits;
        bits_left -= level_bits;

        if (next) {
            shortest = next->shortest;
            /*check to see if the node is data or internal */
            if (trie_get_type(next) == PREFIX_TRIE_TYPE_DATA) {
                /* we've hit a leaf */
                /* note that the search key's prefix must be >= leaf key,
                 * otherwise the leaf key would be matching on "phantom" bits
                 */
                //printf("comparing to key at bit %u to %u: %s\n", total_bits, (prefix > next->len ? next->len - total_bits : bits_left),__hexdump(next->key, next->len / 8 + (next->len % 8 > 0 ? 1 : 0), buffer, 128));
                //printf("prefix key: %s\n", __hexdump(key, prefix / 8 + (prefix % 8 > 0 ? 1 : 0), buffer, 128));
                if (prefix == next->len
                    && is_bitstring_equal(key, next->key, total_bits,
                                          (prefix >
                                           next->len ? next->len -
                                           total_bits : bits_left)) == TRUE) {
                    return TRUE;
                }
                /*search the prefix tree */
                //printf("search the data prefix tree\n");
                search_prefix_exact(next->prefix, key, prefix, total_bits,
                                    &found);
                return found;
            }

            /* follow the path - may not need to key-compare again here, but it would
             * fail-fast and avoid unnecessary trie traversals on a full path-compressed
             * leaf lookup
             */
            node = (struct prefix_trie_node *) next;
            //printf("following the node path: %s\n", print_trie_node(node, total_bits));

            if (prefix - total_bits <= node->skip
                || !is_bitstring_equal(key, next->key, total_bits,
                                       (prefix - total_bits >
                                        node->skip ? node->skip : bits_left))) {
                //printf("searching prefix: bits left %u node skip: %u total bits: %u\n", bits_left,node->skip, total_bits);
                search_prefix_exact(next->prefix, key, prefix, total_bits,
                                    &found);
                return found;
            }

            total_bits += node->skip;
            bits_left -= node->skip;
            /*continue */
            level_bits = get_branch_bits(node);
            branches =
                (struct prefix_trie_data **) (((uint8_t *) node) +
                                              sizeof(*node));
        } else {
            return FALSE;
        }
    }

    branch_index =
        extract_bit_value(total_bits, bits_left,
                          key) << (level_bits - bits_left);
    //printf("we're somewhere in the middle - find the right branch value: %i\n", branch_index);
    next = branches[branch_index];

    if (next) {
        /*we could be a prefix */
        if (trie_get_type(next) == PREFIX_TRIE_TYPE_DATA) {
            if (next->len > prefix) {
                search_prefix(next->prefix, key, prefix, total_bits, &found);
                return found;
            }
            if (next->len < prefix) {
                return FALSE;
            }
            /*next->len cannot be < prefix */
            return TRUE;
        }
        /*it's a node - search the prefix */
        search_prefix(next->prefix, key, prefix, total_bits, &found);
        return found;
    }

    return FALSE;
}

void print_trie(struct prefix_trie_struct *trie)
{
    assert(trie);

    printf
        ("Trie: key_len=%zu count=%zu node_count=%zu def_value=%p fill_factor=%f branch_fill=%u shortest=%u max_depth=%zu\n",
         trie->key_len, trie->count, trie->node_count, trie->def_value,
         trie->fill_factor, trie->branch_fill, trie->shortest, trie->max_depth);

    struct prefix_trie_iter iter;
    _prefix_trie_iter_init(&iter, trie, TRUE);

    int count = 0;
    while (prefix_trie_iter_next_print(&iter, NULL, NULL, NULL)) {
        count++;
    }

    assert(count == trie->count);

    prefix_trie_iter_destroy(&iter);
}

char *print_trie_data(struct prefix_trie_data *dnode)
{
    assert(dnode);

    if (dnode->data == NULL) {
        return "<NULL>";
    }
    static char outbuf[256];
    static char keybuf[128];
    /*print out the match prefix and key up to the max len */

    int bytes = dnode->len / 8 + (dnode->len % 8 > 0 ? 1 : 0);
    __hexdump(dnode->key, bytes, keybuf, 128);

    snprintf(outbuf, 128, "%s:%d:%d:%i:%p:%p",
             keybuf, dnode->len, dnode->shortest,
             dnode->ref_count, dnode->data, dnode->prefix);

    return outbuf;
}

char *print_trie_node(struct prefix_trie_node *node, uint8_t offset)
{
    assert(node);

    static char outbuf[256];
    static char keybuf[148];
    /*print out the match prefix and key up to the max len */
    int bytes =
        (offset + node->skip) / 8 + ((offset + node->skip) % 8 > 0 ? 1 : 0);
    __hexdump(node->key, bytes, keybuf, 128);

    snprintf(outbuf, 128, "%s:%u(%u):%u:%u:%u:%d:%p",
             keybuf, offset + node->skip, node->skip,
             node->shortest, get_branch_bits(node),
             get_branch_fill(node), get_branch_full(node), node->prefix);

    return outbuf;
}

static void _prefix_trie_iter_init(struct prefix_trie_iter *iter,
                                   struct prefix_trie_struct *trie,
                                   int print_out)
{
    assert(trie);
    bzero(iter, sizeof(*iter));
    iter->trie = trie;

    struct prefix_trie_iter_node *nnode = NULL;

    /*root iter node */
    struct prefix_trie_iter_node *inode =
        create_iter_node(0, trie->root_branch, 0, 0, NULL, NULL);
    iter->iter_node = inode;

    /*traverse as far down (left) as possible - DFS */

    struct prefix_trie_data *dnode = NULL;
    struct prefix_trie_data *fnode = NULL;

    struct prefix_trie_node *node = NULL;

    int total_len = 0;
    int level_bits = PREFIX_TRIE_ROOT_BIT;

    char buffer[128];
    while (fnode == NULL) {
        int i = 0;
        for (; i < inode->limit; i++) {
            if (inode->branches[i]) {
                inode->branch = i;

                dnode = inode->branches[i];

                if (trie_get_type(dnode) == PREFIX_TRIE_TYPE_DATA) {
                    fnode = dnode;
                } else {
                    node = (struct prefix_trie_node *) dnode;
                }
                break;
            }
        }

        if (fnode == NULL && node == NULL)
            break;

        if (node) {
            total_len += level_bits + node->skip;
            level_bits = get_branch_bits(node);

            nnode = create_iter_node(total_len,
                                     (struct prefix_trie_data
                                      **) (((uint8_t *) node) +
                                           sizeof(*node)), 0,
                                     inode->level + 1, node, inode);

            if (print_out) {
                memset(buffer, ' ', inode->level);
                buffer[inode->level] = 0;
                printf("%snode(%u): %s\n", buffer, inode->branch,
                       print_trie_node(node, nnode->len - nnode->node->skip));
            }

            inode = nnode;
            iter->iter_node = inode;

        }

        node = NULL;
    }

    if (fnode == NULL) {
        free(inode);
        iter->iter_node = NULL;
    }

}

void prefix_trie_iter_init(struct prefix_trie_iter *iter,
                           struct prefix_trie_struct *trie)
{
    _prefix_trie_iter_init(iter, trie, FALSE);
}

static int _prefix_trie_iter_next(struct prefix_trie_iter *iter,
                                  uint8_t ** key, uint16_t * prefix,
                                  void **data, int print_out)
{
    assert(iter);

    if (iter->iter_node == NULL) {
        /*the iter has been destroyed */
        return FALSE;
    }

    struct prefix_trie_iter_node *inode = iter->iter_node;

    //    if(inode->branch >= inode->limit) {
    //        /*no branches or nodes left*/
    //        return FALSE;
    //    }

    memcpy(&iter->last_iter_node, inode, sizeof(*inode));

    char buffer[128];
    /*there is a prefix to traverse */
    if (inode->prefix) {
        assert(inode->prefix->key);
        if (data) {
            *data = inode->prefix->data;
        }

        if (key) {
            *key = inode->prefix->key;
            *prefix = inode->prefix->len;
        }

        if (print_out) {
            memset(buffer, ' ', inode->level + 1);
            buffer[inode->level + 1] = 0;
            printf("%sprefix: %s\n", buffer, print_trie_data(inode->prefix));
        }
        if (inode->prefix->prefix && inode->prefix->prefix->len > inode->len) {
            inode->prefix = inode->prefix->prefix;
            return TRUE;
        }
        inode->prefix = NULL;
    } else {
        assert(inode->branches[inode->branch]);
        assert(inode->branches[inode->branch]->key);

        if (data) {
            *data = inode->branches[inode->branch]->data;
        }
        if (key) {
            *key = inode->branches[inode->branch]->key;
            *prefix = inode->branches[inode->branch]->len;
        }

        if (print_out) {
            memset(buffer, ' ', inode->level);
            buffer[inode->level] = 0;
            printf("%sdata(%u): %s\n", buffer, inode->branch,
                   print_trie_data(inode->branches[inode->branch]));
        }

        if (inode->branches[inode->branch]->prefix
            && inode->branches[inode->branch]->prefix->len > inode->len) {
            inode->prefix = inode->branches[inode->branch]->prefix;
            return TRUE;
        }
    }

    /*the branch index must point to the next leaf data */
    /*traverse as far down (right) as possible - DFS */

    struct prefix_trie_data *dnode = NULL;
    struct prefix_trie_data *fnode = NULL;

    struct prefix_trie_node *node = NULL;

    int total_len = inode->len;
    int level_bits =
        (inode->node ==
         NULL ? PREFIX_TRIE_ROOT_BIT : get_branch_bits(inode->node));

    struct prefix_trie_iter_node *nnode = NULL;

    /*next branch */
    inode->branch++;
    while (fnode == NULL) {

        for (; inode->branch < inode->limit; inode->branch++) {
            if (inode->branches[inode->branch]) {
                dnode = inode->branches[inode->branch];
                if (trie_get_type(dnode) == PREFIX_TRIE_TYPE_DATA) {
                    fnode = dnode;
                } else {
                    node = (struct prefix_trie_node *) dnode;
                }
                break;
            }
        }

        if (fnode == NULL && node == NULL) {
            /*nothing more at this node */
            if (inode->prev == NULL) {
                /*at the root */
                free(inode);
                iter->iter_node = NULL;
                return TRUE;
            }

            iter->iter_node = inode->prev;

            /*no need to check whether the prefix->len > inode->prev->node->len since it should always be the case now */
            if (inode->node && inode->node->prefix) {
                iter->iter_node->prefix = inode->node->prefix;
                free(inode);
                return TRUE;
            }

            total_len -= (inode->len - inode->prev->len);
            level_bits = (inode->prev->node == NULL ? PREFIX_TRIE_ROOT_BIT
                          : get_branch_bits(inode->prev->node));

            free(inode);
            inode = iter->iter_node;
            inode->branch++;
        } else if (node) {
            total_len += level_bits + node->skip;
            level_bits = get_branch_bits(node);

            nnode =
                create_iter_node(total_len,
                                 (struct prefix_trie_data
                                  **) (((uint8_t *) node)
                                       + sizeof(*node)), 0,
                                 inode->level + 1, node, inode);

            if (print_out) {
                memset(buffer, ' ', inode->level);
                buffer[inode->level] = 0;
                printf("%snode(%u): %s\n", buffer, inode->branch,
                       print_trie_node(node, nnode->len - nnode->node->skip));
            }

            inode = nnode;
            iter->iter_node = inode;

        }
        node = NULL;
    }

    return TRUE;
}

int prefix_trie_iter_next(struct prefix_trie_iter *iter, uint8_t ** key,
                          uint16_t * prefix, void **data)
{
    return _prefix_trie_iter_next(iter, key, prefix, data, FALSE);

}

int prefix_trie_iter_next_print(struct prefix_trie_iter *iter,
                                uint8_t ** key, uint16_t * prefix, void **data)
{
    return _prefix_trie_iter_next(iter, key, prefix, data, TRUE);

}

static inline struct prefix_trie_iter_node *get_iter_node_at_level(uint16_t
                                                                   level, struct
                                                                   prefix_trie_iter_node
                                                                   *inode)
{
    assert(inode);

    if (inode->level < level) {
        return NULL;
    }

    while (inode && inode->level > level) {
        inode = inode->prev;
    }
    assert(inode == NULL || inode->level == level);
    return inode;
}

int prefix_trie_iter_remove(struct prefix_trie_iter *iter)
{
    assert(iter);

    /*nothing to remove */
    if (iter->last_iter_node.branch < 0 && iter->last_iter_node.prefix == NULL) {
        return FALSE;
    }
    //printf("ITER REMOVE\n");

    struct prefix_trie_data *next = NULL;
    struct prefix_trie_data *leaf = NULL;

    struct prefix_trie_node *node = NULL;

    struct prefix_trie_iter_node *inode = &iter->last_iter_node;
    struct prefix_trie_iter_node *newnode = NULL;
    struct prefix_trie_iter_node *prevnode = NULL;
    struct prefix_trie_iter_node *tempnode = NULL;

    uint16_t branch = 0;

    if (inode->prefix) {

        set_node_prefix(last_prefix_of
                        (inode->branches[inode->branch],
                         inode->prefix->len), inode->prefix->prefix);

        if ((inode->node && inode->node->shortest == inode->prefix->len)
            || (iter->trie->shortest == inode->prefix->len)) {
            update_shortest(iter->trie, inode);
        }
        //printf("removing last iter prefix: %s\n", print_trie_data(inode->prefix));
        destroy_trie_node(iter->trie, inode->prefix);
        goto out;
    }

    leaf = inode->branches[inode->branch];
    assert(leaf->ref_count == 1);

    //printf("removing last iter leaf: %s\n", print_trie_data(leaf));
    /*if the leaf branch to remove has a prefix, then it will be replaced by the prefix */
    next = leaf->prefix;
    if (set_node_prefix(leaf, NULL)) {
        //printf("replacing leaf node with prefix: %s\n", print_trie_data(next));
        assert(next->ref_count == 0);

        set_branch_child(iter->trie, inode->node, inode->branches,
                         inode->branch, next);

        /*point back to the new leaf as next since the branch should not have changed */
        assert(iter->iter_node->branches[iter->iter_node->branch] == next);
        iter->iter_node->prefix = NULL;
    } else {
        /*otherwise, clear the parent-child reference */
        set_branch_child(iter->trie, inode->node, inode->branches,
                         inode->branch, NULL);
    }

    if ((inode->node && inode->node->shortest == leaf->len)
        || (iter->trie->shortest == leaf->len)) {
        update_shortest(iter->trie, inode);
    }

    destroy_trie_node(iter->trie, leaf);

    if (inode->node) {
        /*check if we need to reduce the node */
        if (get_branch_fill(inode->node) == 1 && inode->prev) {
            /*check if the iter_node node needs to update */
            prevnode =
                get_iter_node_at_level(inode->level + 1, iter->iter_node);
            if (prevnode) {
                newnode = prevnode->prev;
            } else {
                //if(iter->iter_node->node == inode->node) {
                newnode = iter->iter_node;
            }

            if (inode->node == newnode->node) {
                /* either the current iter is at the same node, just at the next non-null leaf branch
                 * or it has descended down a branch rooted at the same node.
                 */

                next = newnode->branches[newnode->branch];

                //printf("replacing node with singleton child, prev branch: %u which is next: %s\n", inode->prev->branch, print_trie_data(next));

                branch = inode->prev->branch;

                /*no need to update the branch index, since it points to the next node already */
                //                if(iter->iter_node->node == inode->node) {
                //                    iter->iter_node = inode->prev;
                //                } else {
                //                    prevnode->prev = inode->prev;
                //                }


                if (prevnode) {
                    prevnode->prev = inode->prev;
                } else {
                    iter->iter_node = inode->prev;
                }

                free(newnode);

            } else if (prevnode == NULL || inode->node != newnode->node) {
                /*the current iter node is the prev */
                /*find the right place to insert the branch which must be < the current branch */
                next = find_singleton_child(inode->node);
                assert(next);
                //printf("cur=prev replacing node with singleton child, which is next: %s\n",print_trie_data(next));

                //branch = extract_bit_value(inode->prev->len, get_branch_bits(inode->prev->node),
                //        next->key);

                branch = get_branch_index(next, inode->prev->len,
                                          get_branch_bits(inode->prev->node));

                assert(branch < iter->iter_node->branch);
            }

            set_branch_child(iter->trie, inode->prev->node,
                             inode->prev->branches, branch, next);

            /*if the node had a prefix, then the child must inherit it */
            if (inode->node->prefix) {
                insert_prefix(iter->trie, next, inode->node->prefix, FALSE);
            }

            if (trie_get_type(next) != PREFIX_TRIE_TYPE_DATA) {
                ((struct prefix_trie_node *) next)->skip +=
                    get_branch_bits(inode->node)
                    + inode->node->skip;
            }

            destroy_trie_node(iter->trie,
                              (struct prefix_trie_data *) inode->node);
            goto out;
        } else if (should_halve(iter->trie, inode->node)) {
            /*check if the node should halve */
            /*check if the iter_node node needs to update */
            //printf("halving the remaining node: %s\n", print_trie_node(inode->node, inode->len));
            next = halve_node(iter->trie, inode->node);

            prevnode =
                get_iter_node_at_level(inode->level + 1, iter->iter_node);
            if (prevnode) {
                newnode = prevnode->prev;
            } else {
                //if(iter->iter_node->node == inode->node) {
                newnode = iter->iter_node;
            }

            if (inode->node == newnode->node) {
                /*we can update the prev branch easily */
                branch = inode->prev->branch;
                set_branch_child(iter->trie, inode->prev->node,
                                 inode->prev->branches, branch, next);

                /* since we halved the node - reduced its bits by one - and gave it new children
                 * we need to traverse the children to find the right "next node" corresponding
                 * to the current branch. create a new iter node for the child and re-link.
                 */

                newnode->node = (struct prefix_trie_node *) next;
                newnode->branches = newnode->node->branches;
                newnode->limit >>= 1;
                next = newnode->branches[newnode->branch >> 1];

                if (trie_get_type(next) == PREFIX_TRIE_TYPE_DATA
                    || ((struct prefix_trie_node *) next)->skip > 0) {
                    /*adjust the previous branch bit by one */
                    newnode->branch >>= 1;

                } else {
                    node = (struct prefix_trie_node *) next;

                    /*the child can only have 1 bit */
                    tempnode =
                        create_iter_node(newnode->len +
                                         get_branch_bits(newnode->node) -
                                         1, node->branches,
                                         newnode->branch % 2,
                                         newnode->level + 1, node, newnode);

                    /*adjust the previous branch bit by one */
                    newnode->branch >>= 1;
                    //                    if(iter->iter_node->node == inode->node) {
                    //                        iter->iter_node = tempnode;
                    //                    } else {
                    //                        prevnode->prev = tempnode;
                    //                    }

                    if (prevnode) {
                        prevnode->prev = tempnode;
                    } else {
                        iter->iter_node = tempnode;
                    }

                }

            } else if (prevnode == NULL || inode->node != newnode->node) {

                //                branch = extract_bit_value(inode->prev->len,
                //                        (inode->prev->node == NULL ? PREFIX_TRIE_ROOT_BIT
                //                                : get_branch_bits(inode->prev->node)), next->key);

                branch = get_branch_index(next, inode->prev->len,
                                          (inode->prev->node ==
                                           NULL ? PREFIX_TRIE_ROOT_BIT :
                                           get_branch_bits(inode->prev->node)));

                assert(branch < iter->iter_node->branch);
                set_branch_child(iter->trie, inode->prev->node,
                                 inode->prev->branches, branch, next);
            }
            destroy_trie_node(iter->trie,
                              (struct prefix_trie_data *) inode->node);
            goto out;
        }
    }

    /*or bzero the last_iter_node */
 out:inode->node = NULL;
    inode->branch = -1;
    inode->prefix = NULL;

    return TRUE;
}

void prefix_trie_iter_destroy(struct prefix_trie_iter *iter)
{
    assert(iter);

    struct prefix_trie_iter_node *inode = iter->iter_node;

    while (inode) {
        inode = inode->prev;
        free(iter->iter_node);
        iter->iter_node = inode;
    }
}

uint32_t prefix_trie_count(struct prefix_trie_struct *trie)
{
    return trie->count;
}

uint32_t prefix_trie_node_count(struct prefix_trie_struct * trie)
{
    return trie->node_count;
}
