/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- 
 *
 * Implementation of a radix tree to store string prefixes.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#ifndef __RADIXTREE_H__
#define __RADIXTREE_H__

#include <serval/platform.h>
#include <serval/debug.h>
#include <serval/list.h>

enum node_state {
        NODE_ACTIVE,
        NODE_INACTIVE,
};

struct radix_node;

struct radix_node_ops {
        int (*init)(struct radix_node *);
        void (*destroy)(struct radix_node *);
        const char *(*print)(struct radix_node *, char *, size_t);
};

struct radix_node {
        enum node_state state;
        unsigned int id;
        struct radix_node *parent;
        struct list_head lh;
        struct list_head plh;
        struct list_head children;
        size_t alloclen, strlen;
        void *private;
        char *str;
};

struct radix_tree {
        struct radix_node root;
};

#define RADIX_TREE_DEFINE(t)                                            \
        struct radix_tree t = {                                         \
                .root = {                                               \
                        .state = NODE_INACTIVE,                         \
                        .parent = NULL,                                 \
                        .lh = { &t.root.lh, &t.root.lh },               \
                        .children = { &t.root.children,                 \
                                      &t.root.children },               \
                        .str = "\0",                                    \
                }                                                       \
        };

#define RADIX_TREE_INIT(t)                                              \
        (t)->root = {                                                   \
                .state = NODE_INACTIVE,                                 \
                .parent = NULL,                                         \
                .lh = { &t->root.lh, &t->root.lh },                     \
                .children = { &t->root.children,                        \
                              &t->root.children },                      \
                .str = "\0",                                            \
        };

int radix_tree_init(struct radix_tree *tree);
int radix_node_init(struct radix_node *n,
                    struct radix_node *parent,
                    void *private);
int radix_node_set_key(struct radix_node *n, 
                       const char *str, 
                       size_t strlen, 
                       gfp_t alloc);
const char *radix_node_get_key(struct radix_node *n);
size_t radix_node_get_keylen(struct radix_node *n);
int radix_node_is_wildcard(struct radix_node *n);
int radix_node_is_active(struct radix_node *n);

void *radix_node_get_priv(struct radix_node *n);
const char *radix_node_print(struct radix_node *n, char *buf, size_t buflen);
int radix_tree_insert(struct radix_tree *tree, const char *str, 
                      void *private, struct radix_node **node, gfp_t alloc);
struct radix_node *radix_tree_find(struct radix_tree *tree, const char *str);
int radix_node_remove(struct radix_node *node, gfp_t alloc);
int radix_tree_remove(struct radix_tree *tree, const char *str, gfp_t alloc);
void radix_tree_destroy(struct radix_tree *tree);
int radix_tree_foreach(struct radix_tree *tree, 
                       int (*node_func)(struct radix_node *, void *arg),
                       void *arg);

#define radix_node_private(n, type) ((type *)n->private)

#endif /* __RADIXTREE_H */
