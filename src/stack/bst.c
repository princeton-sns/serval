/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/platform.h>
#include <scaffold/debug.h>
#if defined(OS_USER)
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#endif
#if defined(OS_LINUX_KERNEL)
#include <linux/kernel.h>
#include <linux/string.h>
#endif
#include "bst.h"

#define PREFIX_BYTE(bits) ((bits) / 8)
#define PREFIX_SIZE(bits) (PREFIX_BYTE(bits) + (((bits) % 8) ? 1 : 0))
#define CHECK_BIT(prefix, bitoffset) (((char *)prefix)[PREFIX_BYTE(bitoffset)] \
				      & (0x1 << (7 - ((bitoffset) % 8))))

/*
  struct bst_node:

  A node in a prefix-based binary search tree.

  flags: 

  BST_FLAG_ACTIVE: set if the node is an active prefix, i.e., the node
  represents is not just a necessary node because of active prefixes
  in its sub trees.
 */

enum bst_node_flag {
        BST_FLAG_ACTIVE,
};

struct bst_node {       
        struct bst *tree;
	struct bst_node *parent, *left, *right;
        struct bst_node_ops *ops;
	unsigned char flags;
        void *private;
	unsigned int prefix_bits; 
	unsigned char prefix[0];
};

unsigned int bst_node_get_prefix_size(struct bst_node *n)
{
        return PREFIX_SIZE(n->prefix_bits);
}

static int bst_node_flag(struct bst_node *n, enum bst_node_flag flag)
{
        return (n->flags & (0x1 << flag));
}

static void bst_node_set_flag(struct bst_node *n, enum bst_node_flag flag)
{
        n->flags |= (0x1 << flag);
}

static void bst_node_reset_flag(struct bst_node *n, enum bst_node_flag flag)
{
        n->flags &= ((0x1 << flag) ^ -1U);
}

void *bst_node_get_private(struct bst_node *n)
{
        return n->private;
}

unsigned int bst_node_prefix_bits(struct bst_node *n)
{
        return n->prefix_bits;
}

int bst_node_print_prefix(struct bst_node *n, char *buf, int buflen)
{
        unsigned int i;
        int len = 0;
        
        if (buflen <= 0)
                return 0;

        if (n->prefix_bits == 0) {
                len += snprintf(buf, buflen - len, "0");
        }
        for (i = 0; i < PREFIX_SIZE(n->prefix_bits); i++) {
                len += snprintf(&buf[i*2], buflen - len, "%02x", 
                                n->prefix[i] & 0xff);
        }
        return len;
}

int bst_node_print_recursive(struct bst_node *n, char *buf, int buflen)
{
        int len = 0;

        if (buflen <= 0)
                return len;

	if (n) {
		if (bst_node_flag(n, BST_FLAG_ACTIVE)) {
                        if (n->ops && n->ops->print) {
                                len += n->ops->print(n, buf + len, 
                                                     buflen - len);
                        }
                        /*
                          if (buflen - len > 0) {
                                buf[len++] = '\n';
                        }
                        */
                }
		len += bst_node_print_recursive(n->left, buf + len, 
                                                buflen - len);
		len += bst_node_print_recursive(n->right, buf + len, 
                                                buflen - len);
	}

        return len;
}

struct bst_node *bst_node_find_longest_prefix(struct bst_node *n,
                                              struct bst_node **prev,
                                              void *prefix,
                                              unsigned int prefix_bits)
{
        if (!n)
                return NULL;

        /* Keep track of the previous active node */
        if (bst_node_flag(n, BST_FLAG_ACTIVE))
                *prev = n;

	if (n->prefix_bits == prefix_bits)
		goto out;
	
        if (prefix_bits == 0) {
                /* must be the root node */
                goto out;
        }
        
	/* check if next bit is zero or one and, based on that, go
	 * left or right */
	if (CHECK_BIT(prefix, n->prefix_bits)) {
		if (n->right) {
			return bst_node_find_longest_prefix(n->right,
                                                            prev,
                                                            prefix, 
                                                            prefix_bits);
		}
	} else {
		if (n->left) {
			return bst_node_find_longest_prefix(n->left,
                                                            prev,
                                                            prefix, 
                                                            prefix_bits);
		}
	}
out:
	return n;
}

struct bst_node *bst_find_longest_prefix(struct bst *tree, 
                                         void *prefix,
                                         unsigned int prefix_bits)
{
        struct bst_node *n, *prev = NULL;
        
        n = bst_node_find_longest_prefix(tree->root, &prev, prefix, prefix_bits);

        if (n && !bst_node_flag(n, BST_FLAG_ACTIVE))
                return prev;
        
        return n;
}

/*
  Free the memory associated with a node. The node should have been
  destroyed first, and not be active 
*/
static void __bst_node_free(struct bst_node *n)
{
        /* Make sure the parent knows this node is dead, unless the
         * parent is the node itself. */
        if (n->parent != n) {
                if (n->parent->right == n)
                        n->parent->right = NULL;
                else
                        n->parent->left = NULL;
        } else {
                n->tree->root = NULL;
        }
        FREE(n);
}

/*
  This function will destroy a node and its associated data. However,
  it will not free the node, as it may still be part of the prefix
  tree. 
 */
static void __bst_node_destroy(struct bst_node *n)
{
        if (bst_node_flag(n, BST_FLAG_ACTIVE)) {
                if (n->ops && n->ops->destroy) {
                        n->ops->destroy(n);
                }
                if (n->tree) {
                        n->tree->entries--;
                }
                bst_node_reset_flag(n, BST_FLAG_ACTIVE);
        }
}

static void __bst_node_remove_recursive(struct bst_node *n)
{
        struct bst_node *parent = n->parent;
       
        __bst_node_destroy(n);

        /* Node still has children, so do not free it and recurse up
         * the tree. */
       	if (n->left || n->right)
		return;

        /* Call recursively to remove all parents up the tree until
         * hitting the first which is still active or have a remaining
         * child */
        if (parent != n && !bst_node_flag(parent, BST_FLAG_ACTIVE)) {
                __bst_node_free(n);
                __bst_node_remove_recursive(parent);
        } else {
                __bst_node_free(n);
        }
}

void bst_node_remove(struct bst_node *n)
{
	__bst_node_remove_recursive(n);
}

/* Destroy a sub-tree by recursing down the children */
static void __bst_destroy_subtree(struct bst_node *n)
{
        if (n->left)
                __bst_destroy_subtree(n->left);
        if (n->right)
                __bst_destroy_subtree(n->right);

        __bst_node_destroy(n);
        __bst_node_free(n);
}

/* Apply function to subtree */
int bst_subtree_func(struct bst_node *n, 
                     int (*func)(struct bst_node *, void *arg),
                     void *arg)
{
        int count = 0, ret;

        if (!n)
                return count;


        if (n->left) {
                ret = bst_subtree_func(n->left, func, arg);
                if (ret < 0)
                        return ret;
                count += ret;
        }
        
        if (n->right) {
                ret = bst_subtree_func(n->right, func, arg);
                if (ret < 0)
                        return ret;
                count += ret;
        }

        ret = func(n, arg);
        
        if (ret < 0)
                return ret;
        
        count += ret;

        return count;
}

int bst_init(struct bst *t)
{
        t->root = NULL;
        t->entries = 0;

        return 0;
}

void bst_destroy(struct bst *tree)
{
        if (tree->entries > 0) {
                __bst_destroy_subtree(tree->root);
                tree->root = NULL;
                tree->entries = 0;
        }
}

static int bst_node_init(struct bst_node *n,
                         struct bst_node_ops *ops, 
                         void *private)
{
        if (n->ops)
                return -1;
        
        if (n->private)
                return -1;

        n->ops = ops;
        n->private = private;
        
        if (ops && ops->init) {
                if (ops->init(n) < 0) {
                        return -1;
                }
        }
        return 0;
}

static struct bst_node *bst_node_new(struct bst_node *parent,
                                     struct bst_node_ops *ops,
                                     void *private,
				     void *prefix, 
				     unsigned int prefix_bits,
                                     gfp_t alloc)
{
	struct bst_node *n;
	unsigned long prefix_sz = PREFIX_SIZE(parent->prefix_bits + 1);
	unsigned long sz = sizeof(*n) + prefix_sz;
	unsigned char endmask = 0;
	unsigned int i;

	n = (struct bst_node *)MALLOC(sz, alloc);
	
	if (!n)
		return NULL;
	
	memset(n, 0, sz);
	
	if (CHECK_BIT(prefix, parent->prefix_bits)) {
		parent->right = n;
	} else {
		parent->left = n;
	}
        n->tree = parent->tree;
	n->left = NULL;
	n->right = NULL;
	n->parent = parent;
	n->flags = 0;
	n->prefix_bits = parent->prefix_bits + 1;
	memcpy(n->prefix, prefix, prefix_sz);

        if (bst_node_init(n, ops, private) == -1) {
                FREE(n);
                return NULL;
        }
	/* 
	   Compute a mask that zeros out the extra bits that we might
	   have copied in the last byte of the prefix.
	*/
	
	if (n->prefix_bits % 8) {
		for (i = 0; i < n->prefix_bits % 8; i++) {
			endmask |= (0x1 << (7-i));
		}
		
		n->prefix[prefix_sz-1] &= endmask;
	}
    
	if (parent->prefix_bits + 1 != prefix_bits)
		return bst_node_new(n, ops, private, prefix, 
                                    prefix_bits, alloc);
			 
	return n;
}

struct bst_node *bst_node_insert_prefix(struct bst_node *root, 
                                        struct bst_node_ops *ops, 
                                        void *private, void *prefix, 
                                        unsigned int prefix_bits,
                                        gfp_t alloc)
{
	struct bst_node *n, *prev = NULL;
        
	n = bst_node_find_longest_prefix(root, &prev, prefix, prefix_bits);	
	
	/*
          printf("found %p %p %p %p %u %u\n", 
          n, n->parent,
          n->left, n->right,
          n->prefix_bits, 
          bst_node_flag(n, BST_FLAG_ACTIVE));
        */
        if (n->prefix_bits < prefix_bits) {
                n = bst_node_new(n, ops, private, prefix, prefix_bits, alloc);
		
		if (!n)
			return NULL;

	} else {
                if (bst_node_init(n, ops, private) == -1)
                        return NULL;
        }
        
        bst_node_set_flag(n, BST_FLAG_ACTIVE);
      
	return n;
}

struct bst_node *bst_insert_prefix(struct bst *tree, struct bst_node_ops *ops, 
                                   void *private, void *prefix, 
                                   unsigned int prefix_bits,
                                   gfp_t alloc)
{
        struct bst_node *n;

        if (tree->entries == 0) {
                tree->root = (struct bst_node *)MALLOC(sizeof(struct bst_node), 
                                                       alloc);
                
                if (!tree->root)
                        return NULL;

                memset(tree->root, 0, sizeof(*tree->root));
                tree->root->left = tree->root->right = NULL;
                tree->root->parent = tree->root;
                tree->root->flags = 0;
                tree->root->prefix_bits = 0;
                tree->root->tree = tree;
        }

        n = bst_node_insert_prefix(tree->root, ops, private, 
                                   prefix, prefix_bits, alloc);

        if (n) {
                tree->entries++;
        }

        return n;
}

void bst_remove_node(struct bst *tree, struct bst_node *n)
{
        bst_node_remove(n);
}

void bst_remove_prefix(struct bst *tree, void *prefix, unsigned int prefix_bits)
{
        struct bst_node *n;

        n = bst_find_longest_prefix(tree, prefix, prefix_bits);
        
        if (n) {
                bst_remove_node(tree, n);
        }
}

int bst_print(struct bst *tree, char *buf, int buflen)
{
        if (!tree || tree->entries == 0)
                return 0;

        return bst_node_print_recursive(tree->root, buf, buflen);
}

static int bst_node_init_default(struct bst_node *n)
{
        return 0;
}

static void bst_node_destroy_default(struct bst_node *n)
{

}

struct bst_node_ops default_bst_node_ops = {
        .init = bst_node_init_default,
        .destroy = bst_node_destroy_default,
};

#if defined(ENABLE_MAIN)
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFLEN 2000


static int print_ip_entry(struct bst_node *n, char *buf, int buflen)
{
	struct in_addr addr;
        
        memset(&addr, 0, sizeof(addr));
        memcpy(&addr, n->prefix, PREFIX_SIZE(n->prefix_bits));
        
        return snprintf(buf, buflen, "\t%s", inet_ntoa(addr));
}

static struct bst_node_ops ip_ops = {
        .init = bst_node_init_default,
        .destroy = bst_node_destroy_default,
        .print = print_ip_entry
};

int main(int argc, char **argv)
{
	struct bst root;
	struct in_addr addr;
        char buf[BUFLEN];

	bst_init(&root);

	inet_aton("192.168.1.0", &addr);
	bst_insert_prefix(&root, &ip_ops, NULL, &addr, 24, 0);
	
	inet_aton("192.168.1.253", &addr);
	bst_insert_prefix(&root, &ip_ops, NULL, &addr, 26, 0);

	inet_aton("192.168.2.0", &addr);
	bst_insert_prefix(&root, &ip_ops, NULL, &addr, 25, 0);

	inet_aton("192.168.2.250", &addr);
	bst_insert_prefix(&root, &ip_ops, NULL, &addr, 27, 0);


	bst_insert_prefix(&root, &ip_ops, NULL, NULL, 0, 0);

	bst_print(&root, buf, BUFLEN);
        
        printf("%s", buf);
       
	printf("remove:\n");

	inet_aton("192.168.1.0", &addr);

        bst_remove_prefix(&root, &addr, 24, 0);

	bst_print(&root, buf, BUFLEN);

        printf("%s", buf);
       
	bst_destroy(&root);

	return 0;
}

#endif
