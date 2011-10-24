/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef _HEAP_H_
#define _HEAP_H_

#include "platform.h"

typedef struct heapitem {
    unsigned int index;
    unsigned char active;
} heapitem_t;

typedef struct heap {
    unsigned int max_size;
    unsigned int size;
    int (*cmp)(const struct heapitem *i1, const struct heapitem *i2);
    struct heapitem **map;
} heap_t;

int heap_init(struct heap *h, unsigned int max_size, 
              int (*cmp)(const struct heapitem *i1, const struct heapitem *i2));
void heap_fini(struct heap *h);
int heap_empty(struct heap *h);
int heap_full(struct heap *h);
struct heapitem *heap_front(struct heap *h);
unsigned int heap_size(struct heap *h);
int heap_insert(struct heap *h, struct heapitem *item);
struct heapitem *heap_remove(struct heap *h, unsigned int index);
static inline struct heapitem *heap_remove_first(struct heap *h)
{
    return heap_remove(h, 0);
}

#define heap_entry(ptr, type, member)           \
    container_of(ptr, type, member)

#define heap_first_entry(heap, type, member)        \
    container_of(heap_front(heap), type, member)

#define heap_remove_first_entry(heap, type, member)  \
    container_of(heap_remove_first(heap), type, member)

#endif /* _HEAP_H_ */
