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

struct bst_node {
	struct bst_node *parent, *left, *right;
	unsigned char valid; /* 1 if node represents a prefix, 0 otherwise */
	unsigned int prefix_bits; /* Number of bits in prefix */
	unsigned char prefix[0];
};

#define PREFIX_BYTE(bits) ((bits) / 8)
#define PREFIX_SIZE(bits) (PREFIX_BYTE(bits) + (((bits) % 8) ? 1 : 0))
#define CHECK_BIT(prefix, bitoffset) (((char *)prefix)[PREFIX_BYTE(bitoffset)] \
				      & (1 << (7 - ((bitoffset) % 8))))

void bst_root_init(struct bst_node *r)
{
	r->left = r->right = NULL;
	r->parent = r;
	r->valid = 0;
	r->prefix_bits = 0;
}

void bst_node_print(struct bst_node *n)
{
	if (n) {
		const unsigned int bufsize = PREFIX_SIZE(n->prefix_bits)*2 + 2;
		char buf[bufsize];
		unsigned int i;
		
		if (n->valid) {
			buf[0] = '-';
			buf[1] = '\0';
			
			if (bufsize > 1) {
				for (i = 0; i < PREFIX_SIZE(n->prefix_bits); i++) {
					sprintf(&buf[i*2], "%02x", n->prefix[i] & 0xff);
				}
			} 
			
			LOG_DBG("%p %p %p %p %s %u %u\n", 
                                n, n->parent,
                                n->left, n->right,
                                buf, n->prefix_bits, 
                                n->valid);
		}
		bst_node_print(n->left);
		bst_node_print(n->right);
	}
}

struct bst_node *bst_find_longest_prefix_node(struct bst_node *n, 
					      void *prefix,
					      unsigned int prefix_bits)
{
	if (!n || n->prefix_bits == prefix_bits)
		return n;
	
	/* check if next bit is zero or one and, based on that, go
	 * left or right */
	if (CHECK_BIT(prefix, n->prefix_bits)) {
		if (n->right) {
			return bst_find_longest_prefix_node(n->right, 
							    prefix, 
							    prefix_bits);
		}
	} else {
		if (n->left) {
			return bst_find_longest_prefix_node(n->left, 
							    prefix, 
							    prefix_bits);
		}
	}
	return n;
}

static void __bst_node_remove(struct bst_node *n)
{
	struct bst_node *parent = n->parent;

	if (n->valid || n->left || n->right)
		return;

	if (parent->right == n)
		parent->right = NULL;
	else
		parent->left = NULL;

	FREE(n);

	__bst_node_remove(n->parent);
}

void bst_node_remove(struct bst_node *n)
{
	n->valid = 0;
	__bst_node_remove(n);
}

static void __bst_destroy(struct bst_node *n)
{
	if (!n)
		return;

	__bst_destroy(n->left);
	__bst_destroy(n->right);
	FREE(n);
}

void bst_destroy(struct bst_node *r)
{
	__bst_destroy(r->left);
	__bst_destroy(r->right);
}

static struct bst_node *bst_node_new(struct bst_node *parent, 
				     void *prefix, 
				     unsigned int prefix_bits)
{
	struct bst_node *n;
	unsigned long prefix_sz = PREFIX_SIZE(parent->prefix_bits + 1);
	unsigned long sz = sizeof(*n) + prefix_sz;
	unsigned char endmask = 0;
	unsigned int i;

        /* Perhaps we should use GFP_ATOMIC here... can we guarantee
         * that this is always called from user context? */
	n = (struct bst_node *)MALLOC(sz, GFP_KERNEL);
	
	if (!n)
		return NULL;
	
	memset(n, 0, sz);
	
	if (CHECK_BIT(prefix, parent->prefix_bits)) {
		parent->right = n;
	} else {
		parent->left = n;
	}
	n->left = NULL;
	n->right = NULL;
	n->parent = parent;
	n->valid = 0;
	n->prefix_bits = parent->prefix_bits + 1;
	memcpy(n->prefix, prefix, prefix_sz);

	/* 
	   Compute a mask that zeros out the extra bits that we might
	   have copied in the last byte of the prefix.
	*/
	
	if (n->prefix_bits % 8) {
		for (i = 0; i < n->prefix_bits % 8; i++) {
			endmask |= (1 << (7-i));
		}
		
		n->prefix[prefix_sz-1] &= endmask;
	}

	if (parent->prefix_bits + 1 != prefix_bits)
		return bst_node_new(n, prefix, prefix_bits);
			 
	return n;
}

int bst_add_prefix(struct bst_node *r, void *prefix, unsigned int prefix_bits)
{
	struct bst_node *n;

	n = bst_find_longest_prefix_node(r, prefix, prefix_bits);	
	
	/*
	printf("found %p %p %p %p %u %u\n", 
	       n, n->parent,
	       n->left, n->right,
	       n->prefix_bits, 
	       n->valid);
	*/
	if (n->prefix_bits < prefix_bits) {
		n = bst_node_new(n, prefix, prefix_bits);
		
		if (!n)
			return -1;
	}

	n->valid = 1;

	return 1;
}

#if defined(ENABLE_MAIN)
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{
	struct bst_node root, *n;
	struct in_addr addr;

	bst_root_init(&root);

	inet_aton("192.168.1.0", &addr);
	bst_add_prefix(&root, &addr, 24);
	
	inet_aton("192.168.1.253", &addr);
	bst_add_prefix(&root, &addr, 26);

	inet_aton("192.168.2.0", &addr);
	bst_add_prefix(&root, &addr, 25);

	inet_aton("192.168.2.250", &addr);
	bst_add_prefix(&root, &addr, 27);

	bst_node_print(&root);

	printf("remove:\n");
	inet_aton("192.168.1.0", &addr);
	n = bst_find_longest_prefix_node(&root, &addr, 24);

	bst_node_remove(n);

	bst_node_print(&root);

	bst_destroy(&root);

	return 0;
}

#endif
