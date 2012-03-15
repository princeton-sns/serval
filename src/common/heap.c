/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- 
 *
 * A simple heap implementation.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#include <string.h>
#include <stdlib.h>
#include <common/heap.h>

#define HEAP_DEFAULT_SIZE 200
#define HEAP_DEFAULT_INCREASE_SIZE 100

int heap_init(struct heap *h, unsigned int max_size, 
              int (*cmp)(const struct heapitem *i1, const struct heapitem *i2))
{
    if (max_size == 0)
        max_size = HEAP_DEFAULT_SIZE;

	h->max_size = max_size;
	h->size = 0;
    h->cmp = cmp;
	h->map = malloc(sizeof(struct heapitem *) * max_size); 
    
    if (!h->map)
        return -1;

    return 0;
}
	
void heap_fini(struct heap *h)
{ 
	free(h->map);
}

int heap_empty(struct heap *h)
{ 
	return h->size == 0; 
}

int heap_full(struct heap *h)
{ 
	return h->size >= h->max_size; 
}

struct heapitem *heap_front(struct heap *h)
{ 
	return h->map[0]; 
}

unsigned int heap_size(struct heap *h) 
{ 
	return h->size; 
}
	
static void heap_heapify(struct heap *h, unsigned int i)
{
	unsigned int l, r, smallest;
	struct heapitem *tmp;

	l = (2 * i) + 1;	/* left child */
	r = l + 1;		/* right child */
    
	if ((l < h->size) && h->cmp(h->map[l], h->map[i]))
		smallest = l;
	else
		smallest = i;

	if ((r < h->size) && h->cmp(h->map[r], h->map[smallest]))
		smallest = r;

	if (smallest == i)
		return;

	/* exchange to maintain heap property */
	tmp = h->map[smallest];
	h->map[smallest] = h->map[i];
	h->map[smallest]->index = smallest;
	h->map[i] = tmp;
	h->map[i]->index = i;
	heap_heapify(h, smallest);
}

static int heap_increase_size(struct heap *h, unsigned int increase_size)
{
    struct heapitem **new_map;
    
	new_map = malloc((h->max_size + increase_size) * 
                     sizeof(struct heapitem *));

	if (!new_map)
        return -1;

	memcpy(new_map, h->map, h->size * sizeof(struct heapitem *));

    free(h->map);

	h->map = new_map;

	h->max_size += increase_size;

	return 0;
}

int heap_insert(struct heap *h, struct heapitem *item)
{
	unsigned int i, parent;
    
	if (heap_full(h)) {
		if (heap_increase_size(h, HEAP_DEFAULT_INCREASE_SIZE)) {
            return -1;
		}
	}

	i = h->size;
	parent = (i - 1) / 2;

	/* find the correct place to insert */
	while ((i > 0) && h->cmp(h->map[parent], item)) {
		h->map[i] = h->map[parent];
		h->map[i]->index = i;
		i = parent;
		parent = (i - 1) / 2;
	}
	h->map[i] = item;
	item->index = i;
	h->size++;
    item->active = 1;

	return 0;
}

struct heapitem *heap_remove(struct heap *h, unsigned int index)
{
    struct heapitem *item;

    if (index >= h->size)
		return NULL;

    item = h->map[index];
    h->size--;
	h->map[index] = h->map[h->size];
	heap_heapify(h, index);
    item->index = 0;
    item->active = 0;

    return item;
}
