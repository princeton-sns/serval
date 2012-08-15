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
#if defined(ENABLE_MAIN)
#define LOG_DBG(format, ...) printf("%s: "format, __func__, ## __VA_ARGS__)
#define LOG_ERR(format, ...) fprintf(stderr, "%s: ERROR "format,        \
                                     __func__, ## __VA_ARGS__)
                                     
#define kmalloc(x,y) malloc(x)
#define krealloc(x,y,z) realloc(x,y)
#define kfree(x) free(x)

#define ENOMEM 1
#define OS_USER
#endif

#if defined(OS_USER)
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#endif
#if defined(OS_LINUX_KERNEL)
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#endif
#include "radixtree.h"


int radix_tree_init(struct radix_tree *tree)
{
        memset(tree, 0, sizeof(*tree));         
        tree->root.state = NODE_INACTIVE;
        tree->root.parent = NULL;
        INIT_LIST_HEAD(&tree->root.lh);
        INIT_LIST_HEAD(&tree->root.children);
        tree->root.str = "\0";
        return 0;
}

int radix_node_init(struct radix_node *n,
                    struct radix_node *parent,
                    void *private)
{
        memset(n, 0, sizeof(*n));
        n->parent = parent;
        n->state = NODE_INACTIVE;
        n->private = private;
        INIT_LIST_HEAD(&n->lh);
        INIT_LIST_HEAD(&n->plh);
        INIT_LIST_HEAD(&n->children);
        return 0;
}

static struct radix_node *radix_node_expand(struct radix_node *n, 
                                            size_t addlen, 
                                            gfp_t alloc)
{
        size_t newlen = n->strlen + addlen + 1;

        /* Set a minimum number of bytes to allocate */
        if (newlen < 10)
                newlen = 10;

        if (n->alloclen >= newlen)
                return n;

        n->str = krealloc(n->str, newlen, alloc);

        if (!n->str)
                return NULL;

        n->alloclen = newlen;

        return n;
}

const char *radix_node_get_key(struct radix_node *n)
{
        return n->str;
}

size_t radix_node_get_keylen(struct radix_node *n)
{
        return n->strlen;
}

int radix_node_is_wildcard(struct radix_node *n)
{
        if (n->strlen > 0)
                return n->str[n->strlen-1] == '*';
        return 0;
}

int radix_node_is_active(struct radix_node *n)
{
        return n->state == NODE_ACTIVE;
}

int radix_node_set_key(struct radix_node *n, 
                       const char *str, 
                       size_t strlen, 
                       gfp_t alloc)
{
        if (strlen > n->strlen) {
                n = radix_node_expand(n, strlen - n->strlen, alloc);

                if (!n)
                        return -ENOMEM;
        }

        n->strlen = strlen;
        if (n->str != str)
                strncpy(n->str, str, strlen);
        n->str[n->strlen] = '\0';

        return 0;
}

static struct radix_node *radix_node_new(const char *str,
                                         size_t strlen,
                                         struct radix_node *parent,
                                         void *private,
                                         gfp_t alloc)
{
        struct radix_node *n;
        
        n = kmalloc(sizeof(*n), alloc);

        if (n) {
                radix_node_init(n, parent, private);
                
                if (radix_node_set_key(n, str, strlen, alloc) < 0) {
                        kfree(n);
                        n = NULL;
                }
        }

        return n;
}

static void radix_node_free(struct radix_node *n)
{
        kfree(n->str);
        kfree(n);
}

void *radix_node_get_priv(struct radix_node *n)
{
        return n->private;
}

static size_t str_match(const char *s1, const char *s2, size_t *len)
{
        size_t i = 0;

        while (s1[i] != '\0' && s2[i] != '\0') {
                if (s1[i] != s2[i])
                        break;
                i++;
        }
        
        if (len) {
                *len = i;
                
                while (s1[*len] != '\0')
                        (*len)++;
        }

        return i;
}

static struct radix_node *radix_node_find_lpm(struct radix_node *n, 
                                              const char *str,
                                              size_t *str_index, /* Current index into str where we are matching */
                                              size_t *str_len, /* Keeps track of current node's strlen */
                                              size_t *match_len, /* How much of current node that matches */
                                              struct radix_node **wildcard) 
{
        if (!n)
                return NULL;

        while (1) {
                struct radix_node *c, *tmp = NULL;
                size_t n_str_index = 0;
                
                if (n->parent) {
                        *match_len = str_match(n->str, &str[*str_index], str_len);                        
                        *str_index += *match_len;

                        if (*str_len != *match_len)
                                break;
                        n_str_index = *match_len - 1;
                }

                list_for_each_entry(c, &n->children, lh) {
                        if (c->str[0] == str[*str_index])
                                tmp = c;
                        else if (c->str[0] == '*') {
                                if (!tmp)
                                        tmp = c;
                                if (wildcard)
                                        *wildcard = c;
                        }
                }
                        
                if (!tmp)
                        break;
                n = tmp;
        }
        
        return n;
}

struct radix_node *radix_tree_find(struct radix_tree *tree, const char *str)
{
       size_t str_index = 0, str_len = 0, match_len = 0;
       struct radix_node *n, *wildcard = NULL;
       
       n = radix_node_find_lpm(&tree->root, str, &str_index, &str_len, &match_len, &wildcard);

       if (n && ((str[str_index] == '\0' && n->str[match_len] == '\0') 
                 || n->str[match_len] == '*'))
               return n;

       if (wildcard)
               return wildcard;

       return NULL;      
}

int radix_tree_insert(struct radix_tree *tree, 
                      const char *str, 
                      void *private,
                      struct radix_node **node,
                      gfp_t alloc)
{
        struct radix_node *n, *c;
        size_t str_index = 0, str_len = 0, match_len = 0;
                
        n = radix_node_find_lpm(&tree->root, str, &str_index, &str_len, &match_len, NULL);
        
        if (!n) 
                return -1;
        
        /* printf("insert '%s' found '%s' str_index=%zu\n", str, n->str, str_index); */

        if (str[str_index] == '\0' && n->str[match_len] == '\0') {
                /* Full match, string already in tree */
                if (node)
                        *node = n;
                return 0;
        } else if (n->str[match_len] != '\0') {
                struct radix_node *p = n->parent;
                
                if (match_len) {
                        /* We need to split this node */
                        printf("split %s at %s match_len=%zu\n", n->str, &n->str[match_len], match_len);
                        
                        p = radix_node_new(n->str, 
                                           match_len, 
                                           n->parent, NULL, alloc);
                        
                        if (!p) 
                                return -ENOMEM;
                        
                        if (radix_node_set_key(n, &n->str[match_len], 
                                               n->strlen - match_len, alloc) < 0) {
                        radix_node_free(p);
                        return -ENOMEM;
                        }
                        n->parent = p;
                        list_del_init(&n->lh);
                        list_add(&n->lh, &p->children);
                        list_add(&p->lh, &n->parent->children);
                        
                        if (node)
                                *node = p;
                }
                n = p;
        }
        
        if (str[str_index] != '\0') {
                printf("adding %s\n", &str[str_index]);
                /* Still need to add the rest of the string */
                c = radix_node_new(&str[str_index], 
                                   strlen(&str[str_index]), 
                                   n, private, alloc);
                
                if (!c)
                        return -1;
                
                c->state = NODE_ACTIVE;
                list_add(&c->lh, &n->children);

                if (node)
                        *node = c;        
        }

        return 1;
}

/*
static size_t str_splice(char *dst, const char *s1, const char *s2)
{
        size_t i = 0;
        
        while (*s1 != '\0') {
                *dst++ = *s1++;
                i++;
        }
        
        while (*s2 != '\0') {
                *dst++ = *s2++;
                i++;
        }
        return i;
}
*/

static int radix_node_merge_child(struct radix_node *n, gfp_t alloc)
{
        struct radix_node *c;
        
        /* We cannot merge an active node or with root */
        if (!n->parent)
                return 0;

        /* We must keep the child node, since it is the ACTIVE one. */
        c = list_first_entry(&n->children, struct radix_node, lh);

        /* Make sure this node can fit the merged string. */
        c = radix_node_expand(c, n->strlen, alloc);

        if (!c)
                return -ENOMEM;
        
        memmove(&c->str[n->strlen], c->str, c->strlen);
        memmove(c->str, n->str,  n->strlen);
        c->strlen = n->strlen + c->strlen;
        c->str[c->strlen] = '\0';

        /* Move the child up. */
        list_replace_init(&n->lh, &c->lh);
        c->parent = n->parent;

        /* Free the node */
        radix_node_free(n);

        return 1;
}

int radix_node_remove(struct radix_node *n, gfp_t alloc)
{
        /* Check whether this is a leaf node or not */
        if (list_empty(&n->children)) {
                struct radix_node *p = n->parent;
                
                /* Leaf node, just remove. */
                list_del(&n->lh);
                radix_node_free(n);
                
                /* We must also check if a sibling leaf node can now
                 * be merged with the parent. This would be the case
                 * if the parent now has a single child. */
                if (p) {
                        if (list_empty(&p->children)) {
                                /* The parent has no children. If the node is
                                 * inactive, we can simply remove it. */
                                if (p->state == NODE_INACTIVE) {
                                        /* Just remove this inactive node */
                                        list_del(&p->lh);
                                        radix_node_free(p);
                                }
                        } else if (list_is_singular(&p->children)) {
                                /* There is a single sibling that we
                                 * can merge with the parent if it is
                                 * inactive */
                                //printf("merging child of %p:%s\n", p, p->str);
                                if (p->state == NODE_INACTIVE)
                                        radix_node_merge_child(p, alloc);
                        }
                }
        } else {
                /* If the node to remove has a single child, we must
                 * check if we can merge it with this node. */
                if (list_is_singular(&n->children)) {
                        //printf("merging child of %p\n", n);
                        radix_node_merge_child(n, alloc);
                } else {
                        /* More than one child, just mark node as
                         * inactive instead of removing. This means it
                         * will be removed as soon as all children are
                         * gone. */
                        n->state = NODE_INACTIVE;
                }
        }        
        return 1;
}

int radix_tree_remove(struct radix_tree *tree, const char *str, gfp_t alloc)
{
        struct radix_node *n;
        size_t str_index = 0, str_len = 0, match_len = 0;
                
        n = radix_node_find_lpm(&tree->root, str, &str_index, &str_len, &match_len, NULL);
        
        if (!n) 
                return -1;
        
        /* Check that the string is actually fully matched */
        if (str[str_index] != '\0')
                return 0;       

        return radix_node_remove(n, alloc);
}

static struct radix_node *list_remove_first(struct list_head *list)
{
        struct radix_node *n;
        
        if (list_empty(list))
                return NULL;
        
        n = list_first_entry(list, struct radix_node, plh);
        list_del_init(&n->plh);

        return n;
}

static void queue_add(struct list_head *q, struct radix_node *n)
{
        list_add_tail(&n->plh, q);
}

static struct radix_node *queue_first(struct list_head *q)
{
        return list_remove_first(q);
}

/*
static void stack_push(struct list_head *stack, struct radix_node *n)
{
        list_add(&n->plh, stack);
}

static struct radix_node *stack_pop(struct list_head *stack)
{
        return list_remove_first(stack);
}
*/

static int radix_tree_foreach_bfs(struct radix_tree *tree, 
                                  int (*node_func)(struct radix_node *, void *arg),
                                  void *arg)
{
        struct list_head queue;
        struct radix_node *n = &tree->root;
        int num_nodes = 0;

        INIT_LIST_HEAD(&queue);

        queue_add(&queue, n);

        while (!list_empty(&queue)) {
                struct radix_node *c, *tmp;
                int ret;
                
                n = queue_first(&queue);
                
                list_for_each_entry_safe(c, tmp, &n->children, lh) {
                        queue_add(&queue, c);
                }

                if (n != &tree->root) {
                        ret = node_func(n, arg);
                        
                        if (ret == -1)
                                break;
                        else if (ret > 0)
                                num_nodes++;
                }
        }
        return num_nodes;
}

int radix_tree_foreach(struct radix_tree *tree, 
                       int (*node_func)(struct radix_node *, void *arg),
                       void *arg)
{
        return radix_tree_foreach_bfs(tree, node_func, arg);
}

static int radix_node_destroy(struct radix_node *n, void *arg)
{
        radix_node_free(n);
        return 1;
}

void radix_tree_destroy(struct radix_tree *tree)
{
        radix_tree_foreach_bfs(tree, radix_node_destroy, NULL);
}

const char *radix_node_print(struct radix_node *n, char *buf, size_t buflen)
{
        if (buflen == 0)
                return buf;
        
        buf[0] = '\0';
        buf[--buflen] = '\0';

        while (n->parent && buflen) {
                size_t len = n->strlen;
                        
                //printf("%s-", n->str);
                if (buflen >= len) {
                        buflen -= len;
                        strncpy(buf + buflen, n->str, len);
                } else {
                        len -= buflen;
                        strncpy(buf, n->str + len, buflen);
                        buflen = 0;
                }
                n = n->parent;
        }

        //printf("\n");
                
        return buf + buflen;
}

static int radix_node_print_active(struct radix_node *n, void *arg)
{
        struct args {
                char *buf;
                size_t buflen;
                int totlen;
        } *args = (struct args *)arg;
        int len = 0;

        if (n->state == NODE_ACTIVE) {
                char node[128];

                len = snprintf(args->buf + args->totlen, args->buflen, "%s\n", 
                               radix_node_print(n, node, sizeof(node) - 1));
                
                if (args->buflen >= len)
                        args->buflen -= len;
                else
                        args->buflen = 0;

                args->totlen += len;
        }

        return len;
}

int radix_tree_print_bfs(struct radix_tree *tree, char *buf, size_t buflen)
{
        struct args {
                char *buf;
                size_t buflen;
                int totlen;
        } args = { buf, buflen, 0 };

        radix_tree_foreach_bfs(tree, radix_node_print_active, &args);

        return args.totlen;
}

const char *test_strings[] = {
        "*",
        "foobar",
        "football",
        "foo*",
        "bar",
        "foobart",
        "badminton",
        "rugby",
        "ruby",
        "bad",
        NULL,
};

/*
static radix_node_ops default_node_ops = {
        .print = radix_node_print,
};
*/

#if defined(ENABLE_MAIN)
static RADIX_TREE_DEFINE(rt);

int main(int argc, char **argv)
{
        unsigned int i;
        struct radix_node *n;
        char buf[128], treestr[1024];
        
        for (i = 0; test_strings[i]; i++) {
                printf("insert %s\n", test_strings[i]);
                radix_tree_insert(&rt, test_strings[i], NULL, &n, 0);
        }
        
        printf("\nprint bfs:\n");

        radix_tree_print_bfs(&rt, treestr, sizeof(treestr));

        printf("%s\n", treestr);

        for (i = 0; test_strings[i]; i++) {
                if (i % 3 == 0) {
                        printf("remove %s\n", test_strings[i]);
                        radix_tree_remove(&rt, test_strings[i], 0);
                }
        }
        
        printf("\nprint bfs:\n");

        radix_tree_print_bfs(&rt, treestr, sizeof(treestr));

        printf("%s\n", treestr);

        for (i = 0; test_strings[i]; i++) {
                char str[128];

                strcpy(str, test_strings[i]);
                
                if (str[strlen(str) - 1] == '*')
                        str[strlen(str) - 1] = '\0';
                
                printf("find %s\n", str);
                
                n = radix_tree_find(&rt, str);
        
                if (n) {
                        printf("\tfound '%s'\n", radix_node_print(n, buf, sizeof(buf)));
                } else {
                        printf("\t%s not found\n", str);
                }
        }

        radix_tree_destroy(&rt);

        return 0;
}
#endif
