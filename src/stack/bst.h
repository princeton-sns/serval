/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _BST_H_
#define _BST_H_

struct bst_node;

struct bst {
        struct bst_node *root;
        unsigned int entries;
};

#define BST_INITIALIZER { NULL, 0 }
 
struct bst_node_ops {
        int (*init)(struct bst_node *);
        void (*destroy)(struct bst_node *);
        int (*print)(struct bst_node *, char *buf, size_t buflen);
};

/*
  Ming:
  Indicates whether a bst_node contains the source rule for service forwarding.
*/

typedef enum bst_node_type {
        DESTINATION, /* specifies the forwarding rule according to destination service */
        SOURCE,      /* specifies the forwarding rule according to source address */
}bst_node_type_t;

extern struct bst_node_ops default_bst_node_ops;

int bst_init(struct bst *tree);
void bst_destroy(struct bst *tree);

/*
  Ming:
  add source address and src_bits
*/
struct bst_node *bst_insert_prefix(struct bst *tree, struct bst_node_ops *ops,
                                   void *private, void *prefix, 
                                   unsigned int prefix_bits,
                                   void * srcaddr, unsigned int src_bits,
                                   gfp_t alloc);
void bst_remove_node(struct bst *tree, struct bst_node *n);
int bst_remove_prefix(struct bst *tree, void *prefix,
                       unsigned int prefix_bits);
void bst_node_remove(struct bst_node *n);

/*
  Ming:
  add source address
*/

struct bst_node *bst_find_longest_prefix(struct bst *tree, 
                                         void *prefix,
                                         unsigned int prefix_bits,
                                         void *srcaddr,
                                         unsigned int src_bits);

struct bst_node *bst_find_longest_prefix_match(struct bst *tree, 
                                               void *prefix,
                                               unsigned int prefix_bits,
                                               void *srcaddr,
                                               unsigned int src_bits,
                                               int (*match)(struct bst_node *));

int bst_node_print_prefix(struct bst_node *n, char *buf, size_t buflen);
int bst_print(struct bst *tree, char *buf, size_t buflen);
void *bst_node_get_private(struct bst_node *n);
const unsigned char *bst_node_get_prefix(const struct bst_node *n);
unsigned int bst_node_get_prefix_size(const struct bst_node *n);
unsigned long bst_node_get_prefix_bits(const struct bst_node *n);
int bst_subtree_func(struct bst_node *n, 
                     int (*func)(struct bst_node *, void *arg), 
                     void *arg);

#define bst_node_private(n, type) ((type *)bst_node_get_private((n)))

/*
  Ming:
  Test program for two dimentional tree
*/

int bst_test();

#endif /* _BST_H_ */
