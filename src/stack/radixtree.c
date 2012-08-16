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
#include <serval/platform.h>
#if defined(OS_USER)
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#endif
#if defined(OS_LINUX_KERNEL)
#include <linux/string.h>
#endif
#include "radixtree.h"

int radix_tree_initialize(struct radix_tree *tree)
{
        memset(tree, 0, sizeof(*tree));         
        tree->root.parent = NULL;
        INIT_LIST_HEAD(&tree->root.lh);
        INIT_LIST_HEAD(&tree->root.children);
        tree->root.str = "\0";
        return 0;
}

int radix_node_initialize(struct radix_node *n,
                          struct radix_node *parent,
                          void *private)
{
        memset(n, 0, sizeof(*n));
        n->parent = parent;
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
        return n->private != NULL;
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
                radix_node_initialize(n, parent, private);
                
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

/**
   This function matches a string as far down the radix tree as
   possible and returns the node at that location. This node may not
   be a perfect match (e.g., we only matched half of the substring in
   the node), but we return it anyway since, for insertions, we may
   want to split the node into two substrings.

   @n          The node to start at (typically the root)
   @str        The string to match
   @str_index  Keeps track of the index into the string 
               we are matching
   @str_len    Keeps track of the string length of the 
               current node
   @match_len  Keeps track of the number of characters matched 
               in the current node
   @match      An optional function used to match only certain
               kinds of nodes.
   @wildcard   An optional node pointer that will keep track of
               the best matching wildcard rule.

   The follwing example illustrates the functionality.
   
   Input string (str): "foob"
   
   Radix tree:

        "\0"
       /    \
     "foo"  "*"
     /   \
   "*"    "bar"

   This example matches the "bar" node, but only up to its first char
   'b', returning:

   match_len = 1   - matching up until 'b' in "bar".
   str_len = 3     - strlen("bar").
   str_index = 4   - matching the entire string "foob".
   wildcard = "*"  - points to the "*" node which is a child of "foo".
 */
static struct radix_node *radix_node_find_lpm(struct radix_node *n, 
                                              const char *str,
                                              size_t *str_index,
                                              size_t *str_len,
                                              size_t *match_len,
                                              int (*match)(struct radix_node *),
                                              struct radix_node **wildcard) 
{
        struct radix_node *prev = n;
        
        if (!n)
                return NULL;

        while (1) {
                struct radix_node *c, *tmp = NULL;
                
                /* Avoid matching root node (parent == NULL) */
                if (n->parent) {
                        *match_len = str_match(n->str, 
                                               &str[*str_index], 
                                               str_len);

                        /* Increase the index into the string we are
                           matching */
                        *str_index += *match_len;

                        if (*str_len != *match_len /* || 
                                                      str[*str_index] == '\0' 
                                                   */) {
                                /* We didn't match the entire node, or
                                   we ran out of characters in the
                                   string, which means we cannot
                                   descend any further */
                                break;
                        }
                }

                /* Keep track of the previously best matching node */
                if (match && match(n))
                        prev = n;

                /* We matched the full node, and there */
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
                        
                if (!tmp) {
                        /* There was no matching child, return the current
                           node as best match */
                        break;
                }
                n = tmp;
        }

        if (match && !match(n))
                n = prev;
        
        return n;
}

struct radix_node *radix_tree_find(struct radix_tree *tree, 
                                   const char *str,
                                   int (*match)(struct radix_node *))
{
       size_t str_index = 0, str_len = 0, match_len = 0;
       struct radix_node *n, *wildcard = NULL;
       
       n = radix_node_find_lpm(&tree->root, str, &str_index, 
                               &str_len, &match_len, match, 
                               &wildcard);

       if (n && ((str[str_index] == '\0' && n->str[match_len] == '\0') 
                 || n->str[match_len] == '*'))
               return n;

       if (wildcard)
               return wildcard;

       return NULL;      
}

int radix_tree_add(struct radix_tree *tree, 
                   const char *str, 
                   void *private,
                   struct radix_node **node,
                   gfp_t alloc)
{
        struct radix_node *n, *c;
        size_t str_index = 0, str_len = 0, match_len = 0;
                
        n = radix_node_find_lpm(&tree->root, str, &str_index, 
                                &str_len, &match_len, NULL, NULL);
        
        if (!n) 
                return -1;
        
        /* printf("insert '%s' found '%s' str_index=%zu\n", 
           str, n->str, str_index); */
                 
        if (str[str_index] == '\0' && n->str[match_len] == '\0') {
                /* Full match, string already in tree */
                if (node)
                        *node = n;
                return 0;
        } else if (n->str[match_len] != '\0') {
                struct radix_node *p = n->parent;
                
                if (match_len) {
                        void *priv = NULL;
                        /* We need to split this node */
                        
                        /*printf("split %s at %s match_len=%zu\n", 
                          n->str, &n->str[match_len], match_len); */
                        
                        if (str[str_index] == '\0') {
                                /* We fully matched the string, so the
                                   parent node resulting from the
                                   split will store the private data
                                   for the node. */
                                priv = private;
                        }
                        
                        p = radix_node_new(n->str, match_len, 
                                           n->parent, priv, alloc);
                        
                        if (!p) 
                                return -ENOMEM;
                        
                        if (radix_node_set_key(n, &n->str[match_len], 
                                               n->strlen - match_len, 
                                               alloc) < 0) {
                                radix_node_free(p);
                                return -ENOMEM;
                        }

                        list_del_init(&n->lh);
                        list_add(&n->lh, &p->children);
                        list_add(&p->lh, &n->parent->children);
                        n->parent = p;

                        if (node)
                                *node = p;
                }
                n = p;
        }
        
        /* The string wasn't fully matched, so we add the rest of the
           string as a new node */
        if (str[str_index] != '\0') {
                //printf("adding %s\n", &str[str_index]);
                /* Still need to add the rest of the string */
                c = radix_node_new(&str[str_index], 
                                   strlen(&str[str_index]), 
                                   n, private, alloc);
                
                if (!c)
                        return -1;
                
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
                                /* The parent has no children. If the
                                 * node is inactive, we can simply
                                 * remove it (unless it is the
                                 * root). */
                                if (!p->private && p->parent) {
                                        /* Just remove this inactive node */
                                        list_del(&p->lh);
                                        radix_node_free(p);
                                }
                        } else if (list_is_singular(&p->children)) {
                                /* There is a single sibling that we
                                 * can merge with the parent if it is
                                 * inactive */
                                //printf("merging child of %p:%s\n", p, p->str);
                                if (!p->private)
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
                        n->private = NULL;
                }
        }        
        return 1;
}

int radix_tree_remove(struct radix_tree *tree, const char *str, gfp_t alloc)
{
        struct radix_node *n;
        size_t str_index = 0, str_len = 0, match_len = 0;
                
        n = radix_node_find_lpm(&tree->root, str, &str_index, 
                                &str_len, &match_len, NULL, NULL);
        
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

static int radix_tree_foreach_bfs(struct radix_tree *tree, 
                                  int (*func)(struct radix_node *, 
                                              void *arg),
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
                        ret = func(n, arg);
                        
                        if (ret == -1)
                                break;
                        else if (ret > 0)
                                num_nodes++;
                }
        }
        return num_nodes;
}

int radix_tree_foreach(struct radix_tree *tree, 
                       int (*func)(struct radix_node *, void *arg),
                       void *arg)
{
        return radix_tree_foreach_bfs(tree, func, arg);
}

static int radix_node_destroy(struct radix_node *n, void *arg)
{
        void (*free_func)(struct radix_node *) = 
                (void (*)(struct radix_node *))arg;

        if (free_func)
                free_func(n);
        radix_node_free(n);
        return 1;
}

void radix_tree_destroy(struct radix_tree *tree,
                        void (*free_func)(struct radix_node *))
{
        radix_tree_foreach_bfs(tree, radix_node_destroy, free_func);
}

int radix_node_print(struct radix_node *n, char *buf, size_t buflen)
{
        struct radix_node *tmp = n;
        char *w, *end = buf + buflen;
        size_t strlen = 0;
        
        memset(buf, '\0', buflen);

        while (tmp->parent) {
                strlen += tmp->strlen;
                tmp = tmp->parent;
        }

        if (strlen > buflen)
                w = buf;
        else
                w = buf + strlen - n->strlen;

        while (n->parent && w >= buf) {
                size_t len = n->strlen > (end - w) ? 
                        (end - w) : n->strlen;
                strncpy(w, n->str, len);
                w -= len;
                n = n->parent;
        }
        
        return (int)strlen;
}

static int radix_node_print_active(struct radix_node *n, void *arg)
{
        struct args {
                char *buf;
                size_t buflen;
                size_t totlen;
        } *args = (struct args *)arg;
        int len = 0;

        if (n->private) {
                len = radix_node_print(n, args->buf + args->totlen, 
                                       args->buflen);                
                if (len > 0) {
                        if (args->buflen >= len)
                                args->buflen -= len;
                        else
                                args->buflen = 0;
                        
                        args->totlen += len;
                }
        }

        return len;
}

int radix_tree_print_bfs(struct radix_tree *tree, char *buf, size_t buflen)
{
        struct args {
                char *buf;
                size_t buflen;
                size_t totlen;
        } args = { buf, buflen, 0 };

        radix_tree_foreach_bfs(tree, radix_node_print_active, &args);

        return (args.buf + args.totlen - buf);
}

#if defined(ENABLE_MAIN)
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

static RADIX_TREE_DEFINE(rt);

int main(int argc, char **argv)
{
        unsigned int i;
        struct radix_node *n;
        char buf[128], treestr[1024];
        
        for (i = 0; test_strings[i]; i++) {
                printf("insert %s\n", test_strings[i]);
                radix_tree_add(&rt, test_strings[i], NULL, &n, 0);
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
                        radix_node_print(n, buf, sizeof(buf));
                        printf("\tfound '%s'\n", buf);
                } else {
                        printf("\t%s not found\n", str);
                }
        }

        radix_tree_destroy(&rt, NULL);

        return 0;
}
#endif
