/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _BST_H_
#define _BST_H_

struct bst_node;

void bst_root_init(struct bst_node *root);
int bst_add_prefix(struct bst_node *root, void *prefix, unsigned int prefix_bits);
void bst_destroy(struct bst_node *root);
void bst_node_remove(struct bst_node *node);
struct bst_node *bst_find_longest_prefix_node(struct bst_node *n, 
					      void *prefix,
					      unsigned int prefix_bits);
#endif /* _BST_H_ */
