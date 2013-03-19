/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <string.h>
#include <sys/uio.h>
#include <serval/debug.h>
#include <serval/platform.h>
#include <serval/lock.h>
#include <serval/skbuff.h>
#include <serval/netdevice.h>
#include <serval/dst.h>

atomic_t num_skb_alloc = ATOMIC_INIT(0);
atomic_t num_skb_clone = ATOMIC_INIT(0);
atomic_t num_skb_free = ATOMIC_INIT(0);

static void skb_release_head_state(struct sk_buff *skb)
{
	/* Release state associated with head */
        if (skb->destructor) {
		skb->destructor(skb);
	}
}

static void skb_release_data(struct sk_buff *skb)
{
	if (!skb->cloned ||
	    !atomic_sub_return(skb->nohdr ? (1 << SKB_DATAREF_SHIFT) + 1 : 1,
			       &skb_shinfo(skb)->dataref)) {
		free(skb->head);
	}
}

/* Free everything but the sk_buff shell. */
static void skb_release_all(struct sk_buff *skb)
{
	skb_release_head_state(skb);
	skb_release_data(skb);
}

void __kfree_skb(struct sk_buff *skb)
{
#if defined(SKB_REFCNT_DEBUG)
        printf("skb %p users=%d -- freeing\n",
               skb, atomic_read(&skb->users));
#endif
	skb_release_all(skb);
	free(skb);
        atomic_inc(&num_skb_free);
}

void kfree_skb(struct sk_buff *skb)
{
	if (likely(!atomic_dec_and_test(&skb->users))) {
#if defined(SKB_REFCNT_DEBUG)
                printf("skb %p users=%d -- NOT freeing\n",
                       skb, atomic_read(&skb->users));
#endif
                return;
        }
	__kfree_skb(skb);
}

struct sk_buff *__alloc_skb(unsigned int size, int fclone, int node)
{
	unsigned char *data;
	struct sk_buff *skb;
	struct skb_shared_info *shinfo;
	
	skb = (struct sk_buff *)malloc(sizeof(struct sk_buff));

	if (!skb)
		return NULL;

        memset(skb, 0, sizeof(*skb));

	data = (unsigned char *)malloc(size + sizeof(struct skb_shared_info));

	if (!data)
		goto nodata;

        memset(data, 0, size + sizeof(struct skb_shared_info));

	/*
	 * Only clear those fields we need to clear, not those that we will
	 * actually initialise below. Hence, don't put any more fields after
	 * the tail pointer in struct sk_buff!
	 */
	//memset(skb, 0, offsetof(struct sk_buff, tail));
	skb->truesize = size + sizeof(struct sk_buff);
	atomic_set(&skb->users, 1);
	skb->head = data;
	skb->data = data;
	skb_reset_tail_pointer(skb);
	skb->end = skb->tail + size;
	skb->mac_header = ~0U;

	/* make sure we initialize shinfo sequentially */
	shinfo = skb_shinfo(skb);
	memset(shinfo, 0, offsetof(struct skb_shared_info, dataref));

	atomic_set(&shinfo->dataref, 1);
#if defined(SKB_REFCNT_DEBUG)
        printf("allocating skb %p\n", skb);
#endif
        atomic_inc(&num_skb_alloc);

	return skb;
nodata:
	free(skb);
	return NULL;
}

static void __copy_skb_header(struct sk_buff *new, const struct sk_buff *old)
{
        new->tstamp             = new->tstamp;
	new->dev		= old->dev;
	new->transport_header	= old->transport_header;
	new->network_header	= old->network_header;
	new->mac_header		= old->mac_header;
	skb_dst_copy(new, old);
	/* new->rxhash		= old->rxhash; */

	memcpy(new->cb, old->cb, sizeof(old->cb));
	new->csum		= old->csum;
	new->pkt_type		= old->pkt_type;
	new->ip_summed		= old->ip_summed;
        //new->skb_iff            = old->skb_iff;
	/* skb_copy_queue_mapping(new, old); */
	new->priority		= old->priority;
	new->protocol		= old->protocol;
	new->mark		= old->mark;
}

/*
 * You should not add any new code to this function.  Add it to
 * __copy_skb_header above instead.
 */
static struct sk_buff *__skb_clone(struct sk_buff *n, struct sk_buff *skb)
{
#define C(x) n->x = skb->x

	n->next = n->prev = NULL;
	n->sk = NULL;
	__copy_skb_header(n, skb);

	C(len);
	C(data_len);
	C(mac_len);
	n->hdr_len = skb->nohdr ? skb_headroom(skb) : skb->hdr_len;
	n->cloned = 1;
	n->nohdr = 0;
	n->destructor = NULL;
	C(tail);
	C(end);
	C(head);
	C(data);
	C(truesize);
	atomic_set(&n->users, 1);

	atomic_inc(&(skb_shinfo(skb)->dataref));
	skb->cloned = 1;

        atomic_inc(&num_skb_clone);

	return n;
#undef C
}

struct sk_buff *skb_clone(struct sk_buff *skb, gfp_t gfp_mask)
{
	struct sk_buff *n;

        n = (struct sk_buff *)malloc(sizeof(*n));
        
        if (!n)
                return NULL;
        
        memset(n, 0, sizeof(*n));

#if defined(SKB_REFCNT_DEBUG)
        printf("cloning skb %p clone %p\n", skb, n);
#endif
        /*
	n = skb + 1;
	if (skb->fclone == SKB_FCLONE_ORIG &&
	    n->fclone == SKB_FCLONE_UNAVAILABLE) {
		atomic_t *fclone_ref = (atomic_t *) (n + 1);
		n->fclone = SKB_FCLONE_CLONE;
		atomic_inc(fclone_ref);
	} else {
		n = kmem_cache_alloc(skbuff_head_cache, gfp_mask);
		if (!n)
			return NULL;

		kmemcheck_annotate_bitfield(n, flags1);
		kmemcheck_annotate_bitfield(n, flags2);
		n->fclone = SKB_FCLONE_UNAVAILABLE;
	}
        */
	return __skb_clone(n, skb);
}

static void copy_skb_header(struct sk_buff *new, const struct sk_buff *old)
{
	__copy_skb_header(new, old);
}

/**
 *	skb_copy	-	create private copy of an sk_buff
 *	@skb: buffer to copy
 *	@gfp_mask: allocation priority
 *
 *	Make a copy of both an &sk_buff and its data. This is used when the
 *	caller wishes to modify the data and needs a private copy of the
 *	data to alter. Returns %NULL on failure or the pointer to the buffer
 *	on success. The returned buffer has a reference count of 1.
 *
 *	As by-product this function converts non-linear &sk_buff to linear
 *	one, so that &sk_buff becomes completely private and caller is allowed
 *	to modify all the data of returned buffer. This means that this
 *	function is not recommended for use in circumstances when only
 *	header is going to be modified. Use pskb_copy() instead.
 */

struct sk_buff *skb_copy(const struct sk_buff *skb, gfp_t gfp_mask)
{
	int headerlen = skb->data - skb->head;
	/*
	 *	Allocate the copy buffer
	 */
	struct sk_buff *n;

	n = alloc_skb(skb->end + skb->data_len, gfp_mask);

	if (!n)
		return NULL;

	/* Set the data pointer */
	skb_reserve(n, headerlen);
	/* Set the tail pointer and length */
	skb_put(n, skb->len);

        /*
	if (skb_copy_bits(skb, -headerlen, n->head, headerlen + skb->len))
		BUG();
        */

	copy_skb_header(n, skb);
	return n;
}

/**
 *	pskb_copy	-	create copy of an sk_buff with private head.
 *	@skb: buffer to copy
 *	@gfp_mask: allocation priority
 *
 *	Make a copy of both an &sk_buff and part of its data, located
 *	in header. Fragmented data remain shared. This is used when
 *	the caller wishes to modify only header of &sk_buff and needs
 *	private copy of the header to alter. Returns %NULL on failure
 *	or the pointer to the buffer on success.
 *	The returned buffer has a reference count of 1.
 */

struct sk_buff *pskb_copy(struct sk_buff *skb, gfp_t gfp_mask)
{
	/*
	 *	Allocate the copy buffer
	 */
	struct sk_buff *n;

	n = alloc_skb(skb->end, gfp_mask);

	if (!n)
		goto out;

	/* Set the data pointer */
	skb_reserve(n, skb->data - skb->head);
	/* Set the tail pointer and length */
	skb_put(n, skb_headlen(skb));
	/* Copy the bytes */
	skb_copy_from_linear_data(skb, n->data, n->len);

	n->truesize += skb->data_len;
	n->data_len  = skb->data_len;
	n->len	     = skb->len;

	copy_skb_header(n, skb);
out:
	return n;
}

/**
 *	pskb_expand_head - reallocate header of &sk_buff
 *	@skb: buffer to reallocate
 *	@nhead: room to add at head
 *	@ntail: room to add at tail
 *	@gfp_mask: allocation priority
 *
 *	Expands (or creates identical copy, if &nhead and &ntail are zero)
 *	header of skb. &sk_buff itself is not changed. &sk_buff MUST have
 *	reference count of 1. Returns zero in the case of success or error,
 *	if expansion failed. In the last case, &sk_buff is not changed.
 *
 *	All the pointers pointing into skb header may change and must be
 *	reloaded after call to this function.
 */

int pskb_expand_head(struct sk_buff *skb, int nhead, int ntail,
		     gfp_t gfp_mask)
{
//	int i;
	u8 *data;
	int size = nhead + skb->end + ntail;
	long off;

	BUG_ON(nhead < 0);
        
	if (skb_shared(skb)) {
		LOG_ERR("skb cannot be shared!\n");
                exit(-1);
        }
        
	size = SKB_DATA_ALIGN(size);

	data = malloc(size + sizeof(struct skb_shared_info));

	if (!data)
		goto nodata;

	/* Copy only real data... and, alas, header. This should be
	 * optimized for the cases when header is void. */
	memcpy(data + nhead, skb->head, skb->tail);
	memcpy(data + size, skb_end_pointer(skb),
	       sizeof(struct skb_shared_info));

/*
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
		get_page(skb_shinfo(skb)->frags[i].page);

	if (skb_has_frags(skb))
		skb_clone_fraglist(skb);
*/
	skb_release_data(skb);

	off = (data + nhead) - skb->head;

	skb->head     = data;
	skb->data    += off;
	skb->end      = size;
	off           = nhead;

	/* {transport,network,mac}_header and tail are relative to skb->head */
	skb->tail	      += off;
	skb->transport_header += off;
	skb->network_header   += off;
	if (skb_mac_header_was_set(skb))
		skb->mac_header += off;
	/* Only adjust this if it actually is csum_start rather than csum */
	if (skb->ip_summed == CHECKSUM_PARTIAL)
		skb->csum_start += nhead;
	skb->cloned   = 0;
	skb->hdr_len  = 0;
	skb->nohdr    = 0;
	atomic_set(&skb_shinfo(skb)->dataref, 1);
	return 0;

nodata:
	return -ENOMEM;
}


/**
 * skb_copy_expand-copy and expand sk_buff
 * @skb: buffer to copy
 * @newheadroom: new free bytes at head
 * @newtailroom: new free bytes at tail
 * @gfp_mask: allocation priority
 *
 * Make a copy of both an &sk_buff and its data and while doing so
 * allocate additional space.
 *
 * This is used when the caller wishes to modify the data and needs a
 * private copy of the data to alter as well as more space for new fields.
 * Returns %NULL on failure or the pointer to the buffer
 * on success. The returned buffer has a reference count of 1.
 *
 * You must pass %GFP_ATOMIC as the allocation priority if this function
 * is called from an interrupt.
 */
struct sk_buff *skb_copy_expand(const struct sk_buff *skb,
                                int newheadroom, int newtailroom,
                                gfp_t gfp_mask)
{
        /*
         * Allocate the copy buffer
         */
        struct sk_buff *n = alloc_skb(newheadroom + skb->len + newtailroom,
                                      gfp_mask);
        int oldheadroom = skb_headroom(skb);
        int head_copy_len, head_copy_off;
        int off;

        if (!n)
                return NULL;

        skb_reserve(n, newheadroom);

        /* Set the tail pointer and length */
        skb_put(n, skb->len);

        head_copy_len = oldheadroom;
        head_copy_off = 0;
        if (newheadroom <= head_copy_len)
                head_copy_len = newheadroom;
        else
                head_copy_off = newheadroom - head_copy_len;

        /* Copy the linear header and data. */
        if (skb_copy_bits(skb, -head_copy_len, n->head + head_copy_off,
                          skb->len + head_copy_len))
                BUG();

        copy_skb_header(n, skb);
        
        off = newheadroom - oldheadroom;
        if (n->ip_summed == CHECKSUM_PARTIAL)
                n->csum_start += off;
#ifdef NET_SKBUFF_DATA_USES_OFFSET
        n->transport_header += off;
        n->network_header   += off;
        if (skb_mac_header_was_set(skb))
                n->mac_header += off;
#endif

        return n;
}

/**
 *	skb_dequeue - remove from the head of the queue
 *	@list: list to dequeue from
 *
 *	Remove the head of the list. The list lock is taken so the function
 *	may be used safely with other locking list functions. The head item is
 *	returned or %NULL if the list is empty.
 */
struct sk_buff *skb_dequeue(struct sk_buff_head *list)
{
	struct sk_buff *result;

	spin_lock_irqsave(&list->lock, 0);
	result = __skb_dequeue(list);
	spin_unlock_irqrestore(&list->lock, 0);
	return result;
}

/**
 *	skb_dequeue_tail - remove from the tail of the queue
 *	@list: list to dequeue from
 *
 *	Remove the tail of the list. The list lock is taken so the function
 *	may be used safely with other locking list functions. The tail item is
 *	returned or %NULL if the list is empty.
 */
struct sk_buff *skb_dequeue_tail(struct sk_buff_head *list)
{
	struct sk_buff *result;

	spin_lock_irqsave(&list->lock, 0);
	result = __skb_dequeue_tail(list);
	spin_unlock_irqrestore(&list->lock, 0);
	return result;
}

/**
 *	skb_queue_purge - empty a list
 *	@list: list to empty
 *
 *	Delete all buffers on an &sk_buff list. Each buffer is removed from
 *	the list and one reference dropped. This function takes the list
 *	lock and is atomic with respect to other list locking functions.
 */
void skb_queue_purge(struct sk_buff_head *list)
{
	struct sk_buff *skb;
	while ((skb = skb_dequeue(list)) != NULL)
		kfree_skb(skb);
}

/**
 *	skb_queue_head - queue a buffer at the list head
 *	@list: list to use
 *	@newsk: buffer to queue
 *
 *	Queue a buffer at the start of the list. This function takes the
 *	list lock and can be used safely with other locking &sk_buff functions
 *	safely.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */
void skb_queue_head(struct sk_buff_head *list, struct sk_buff *newsk)
{
	spin_lock(&list->lock);
	__skb_queue_head(list, newsk);
	spin_unlock(&list->lock);
}

/**
 *	skb_queue_tail - queue a buffer at the list tail
 *	@list: list to use
 *	@newsk: buffer to queue
 *
 *	Queue a buffer at the tail of the list. This function takes the
 *	list lock and can be used safely with other locking &sk_buff functions
 *	safely.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */
void skb_queue_tail(struct sk_buff_head *list, struct sk_buff *newsk)
{
	spin_lock(&list->lock);
	__skb_queue_tail(list, newsk);
	spin_unlock(&list->lock);
}

/**
 *	skb_unlink	-	remove a buffer from a list
 *	@skb: buffer to remove
 *	@list: list to use
 *
 *	Remove a packet from a list. The list locks are taken and this
 *	function is atomic with respect to other list locked calls
 *
 *	You must know what list the SKB is on.
 */
void skb_unlink(struct sk_buff *skb, struct sk_buff_head *list)
{
	spin_lock(&list->lock);
	__skb_unlink(skb, list);
	spin_unlock(&list->lock);
}

/**
 *	skb_append	-	append a buffer
 *	@old: buffer to insert after
 *	@newsk: buffer to insert
 *	@list: list to use
 *
 *	Place a packet after a given packet in a list. The list locks are taken
 *	and this function is atomic with respect to other list locked calls.
 *	A buffer cannot be placed on two lists at the same time.
 */
void skb_append(struct sk_buff *old, struct sk_buff *newsk, struct sk_buff_head *list)
{
	spin_lock(&list->lock);
	__skb_queue_after(list, old, newsk);
	spin_unlock(&list->lock);
}

/**
 *	skb_insert	-	insert a buffer
 *	@old: buffer to insert before
 *	@newsk: buffer to insert
 *	@list: list to use
 *
 *	Place a packet before a given packet in a list. The list locks are
 * 	taken and this function is atomic with respect to other list locked
 *	calls.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */
void skb_insert(struct sk_buff *old, struct sk_buff *newsk, 
                struct sk_buff_head *list)
{
	spin_lock(&list->lock);
	__skb_insert(newsk, old->prev, old, list);
	spin_unlock(&list->lock);
}

int skb_copy_datagram_iovec(const struct sk_buff *skb,
                            int offset, struct iovec *to,
                            int len)
{
        int start = skb_headlen(skb);
        int copy = start - offset;

        if (copy > 0) {
                if (copy > len)
                        copy = len;

                if (memcpy_toiovec(to, skb->data + offset, copy))
                        goto fault;
                if ((len -= copy) == 0)
                        return 0;
                offset += copy;
        }

        if (!len)
                return 0;
fault:
        return -EFAULT;
}

int skb_copy_datagram_from_iovec(struct sk_buff *skb,
                                 int offset,
                                 const struct iovec *from,
                                 int from_offset,
                                 int len)
{
        int start = skb_headlen(skb);
	int copy = start - offset;

	if (copy > 0) {
		if (copy > len)
			copy = len;
		if (memcpy_fromiovecend(skb->data + offset, from, from_offset,
					copy))
			goto fault;
		if ((len -= copy) == 0)
			return 0;
		offset += copy;
		from_offset += copy;
	}
        
        if (!len)
                return 0;
fault:
        return -EFAULT;
}


static inline void skb_split_inside_header(struct sk_buff *skb,
					   struct sk_buff* skb1,
					   const u32 len, const int pos)
{
	int i;
        
	skb_copy_from_linear_data_offset(skb, len, 
                                         skb_put(skb1, pos - len),
					 pos - len);
	/* And move data appendix as is. */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
		skb_shinfo(skb1)->frags[i] = skb_shinfo(skb)->frags[i];

	skb_shinfo(skb1)->nr_frags = skb_shinfo(skb)->nr_frags;
	skb_shinfo(skb)->nr_frags  = 0;
	skb1->data_len		   = skb->data_len;
	skb1->len		   += skb1->data_len;
	skb->data_len		   = 0;
	skb->len		   = len;
	skb_set_tail_pointer(skb, len);
}

static inline void skb_split_no_header(struct sk_buff *skb,
				       struct sk_buff* skb1,
				       const u32 len, int pos)
{
	int k = 0;
	//const int nfrags = skb_shinfo(skb)->nr_frags;

	skb_shinfo(skb)->nr_frags = 0;
	skb1->len		  = skb1->data_len = skb->len - len;
	skb->len		  = len;
	skb->data_len		  = len - pos;
#if 0
	for (i = 0; i < nfrags; i++) {
		int size = skb_shinfo(skb)->frags[i].size;

		if (pos + size > len) {
			skb_shinfo(skb1)->frags[k] = skb_shinfo(skb)->frags[i];

			if (pos < len) {
				/* Split frag.
				 * We have two variants in this case:
				 * 1. Move all the frag to the second
				 *    part, if it is possible. F.e.
				 *    this approach is mandatory for TUX,
				 *    where splitting is expensive.
				 * 2. Split is accurately. We make this.
				 */
				get_page(skb_shinfo(skb)->frags[i].page);
				skb_shinfo(skb1)->frags[0].page_offset += len - pos;
				skb_shinfo(skb1)->frags[0].size -= len - pos;
				skb_shinfo(skb)->frags[i].size	= len - pos;
				skb_shinfo(skb)->nr_frags++;
			}
			k++;
		} else
			skb_shinfo(skb)->nr_frags++;
		pos += size;
	}
#endif
	skb_shinfo(skb1)->nr_frags = k;
}

/**
 * skb_split - Split fragmented skb to two parts at length len.
 * @skb: the buffer to split
 * @skb1: the buffer to receive the second part
 * @len: new length for skb
 */
void skb_split(struct sk_buff *skb, struct sk_buff *skb1, const u32 len)
{
	int pos = skb_headlen(skb);

	if (len < pos)	/* Split line is inside header. */
		skb_split_inside_header(skb, skb1, len, pos);
	else		/* Second chunk has no header, nothing to copy. */
		skb_split_no_header(skb, skb1, len, pos);
}

/* Both of above in one bottle. */

__wsum skb_copy_and_csum_bits(const struct sk_buff *skb, int offset,
                              u8 *to, int len, __wsum csum)
{
	int start = skb_headlen(skb);
	int copy = start - offset;
	//struct sk_buff *frag_iter;
	//int pos = 0;

	/* Copy header. */
	if (copy > 0) {
		if (copy > len)
			copy = len;
                csum = csum_partial_copy_nocheck(skb->data + offset, 
                                                 to, copy, csum);
                
		if ((len -= copy) == 0)
			return csum;
		offset += copy;
		to     += copy;
		//pos	= copy;
	}
        /*
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		int end;

		WARN_ON(start > offset + len);

		end = start + skb_shinfo(skb)->frags[i].size;
		if ((copy = end - offset) > 0) {
			__wsum csum2;
			u8 *vaddr;
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

			if (copy > len)
				copy = len;
			vaddr = kmap_skb_frag(frag);
			csum2 = csum_partial_copy_nocheck(vaddr +
							  frag->page_offset +
							  offset - start, to,
							  copy, 0);
			kunmap_skb_frag(vaddr);
			csum = csum_block_add(csum, csum2, pos);
			if (!(len -= copy))
				return csum;
			offset += copy;
			to     += copy;
			pos    += copy;
		}
		start = end;
	}

	skb_walk_frags(skb, frag_iter) {
		__wsum csum2;
		int end;

		WARN_ON(start > offset + len);

		end = start + frag_iter->len;
		if ((copy = end - offset) > 0) {
			if (copy > len)
				copy = len;
			csum2 = skb_copy_and_csum_bits(frag_iter,
						       offset - start,
						       to, copy, 0);
			csum = csum_block_add(csum, csum2, pos);
			if ((len -= copy) == 0)
				return csum;
			offset += copy;
			to     += copy;
			pos    += copy;
		}
		start = end;
	}
        */
	BUG_ON(len);
	return csum;
}

__sum16 __skb_checksum_complete_head(struct sk_buff *skb, int len)
{
	__sum16 sum;

	sum = csum_fold(skb_checksum(skb, 0, len, skb->csum));
	if (likely(!sum)) {
		/*
                  if (unlikely(skb->ip_summed == CHECKSUM_COMPLETE))
			netdev_rx_csum_fault(skb->dev);
                */
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
	return sum;
}

__sum16 __skb_checksum_complete(struct sk_buff *skb)
{
	return __skb_checksum_complete_head(skb, skb->len);
}

static int skb_copy_and_csum_datagram(const struct sk_buff *skb, 
                                      int offset,
				      u8 __user *to, int len,
				      __wsum *csump)
{
	int start = skb_headlen(skb);
	int copy = start - offset;
        //int i;
	//struct sk_buff *frag_iter;
	//int pos = 0;

	/* Copy header. */
	if (copy > 0) {
		int err = 0;
		if (copy > len)
			copy = len;

                *csump = csum_and_copy_to_user(skb->data + offset, 
                                               to, copy,
                                               *csump, &err);
		if (err)
			goto fault;
		if ((len -= copy) == 0)
			return 0;
		offset += copy;
		to += copy;
		//pos = copy;
	}
/*
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		int end;

		WARN_ON(start > offset + len);

		end = start + skb_shinfo(skb)->frags[i].size;
		if ((copy = end - offset) > 0) {
			__wsum csum2;
			int err = 0;
			u8  *vaddr;
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
			struct page *page = frag->page;

			if (copy > len)
				copy = len;
			vaddr = kmap(page);
			csum2 = csum_and_copy_to_user(vaddr +
							frag->page_offset +
							offset - start,
						      to, copy, 0, &err);
			kunmap(page);
			if (err)
				goto fault;
			*csump = csum_block_add(*csump, csum2, pos);
			if (!(len -= copy))
				return 0;
			offset += copy;
			to += copy;
			pos += copy;
		}
		start = end;
	}

	skb_walk_frags(skb, frag_iter) {
		int end;

		WARN_ON(start > offset + len);

		end = start + frag_iter->len;
		if ((copy = end - offset) > 0) {
			__wsum csum2 = 0;
			if (copy > len)
				copy = len;
			if (skb_copy_and_csum_datagram(frag_iter,
						       offset - start,
						       to, copy,
						       &csum2))
				goto fault;
			*csump = csum_block_add(*csump, csum2, pos);
			if ((len -= copy) == 0)
				return 0;
			offset += copy;
			to += copy;
			pos += copy;
		}
		start = end;
	}
*/
	if (!len)
		return 0;

fault:
	return -EFAULT;
}

/**
 *	skb_copy_and_csum_datagram_iovec - Copy and checkum skb to user iovec.
 *	@skb: skbuff
 *	@hlen: hardware length
 *	@iov: io vector
 *
 *	Caller _must_ check that skb will fit to this iovec.
 *
 *	Returns: 0       - success.
 *		 -EINVAL - checksum failure.
 *		 -EFAULT - fault during copy. Beware, in this case iovec
 *			   can be modified!
 */
int skb_copy_and_csum_datagram_iovec(struct sk_buff *skb,
				     int hlen, struct iovec *iov)
{
	__wsum csum = 0;
	int chunk = skb->len - hlen;

	if (!chunk)
		return 0;

	/* Skip filled elements.
	 * Pretty silly, look at memcpy_toiovec, though 8)
	 */
	while (!iov->iov_len)
		iov++;

	if (iov->iov_len < chunk) {
		if (__skb_checksum_complete(skb))
			goto csum_error;
		if (skb_copy_datagram_iovec(skb, hlen, iov, chunk))
			goto fault;
	} else {
		csum = csum_partial(skb->data, hlen, skb->csum);

		if (skb_copy_and_csum_datagram(skb, hlen, iov->iov_base,
					       chunk, &csum))
			goto fault;
                
		if (csum_fold(csum))
			goto csum_error;
                /*
		if (unlikely(skb->ip_summed == CHECKSUM_COMPLETE))
			netdev_rx_csum_fault(skb->dev);
                */
		iov->iov_len -= chunk;
		iov->iov_base += chunk;
	}
	return 0;
csum_error:
	return -EINVAL;
fault:
	return -EFAULT;
}


/* Copy some data bits from skb to kernel buffer. */
int skb_copy_bits(const struct sk_buff *skb, int offset, void *to, int len)
{
	int start = skb_headlen(skb);
	//struct sk_buff *frag_iter;
	//int i;
        int copy;

	if (offset > (int)skb->len - len)
		goto fault;

	/* Copy header. */
	if ((copy = start - offset) > 0) {
		if (copy > len)
			copy = len;

		skb_copy_from_linear_data_offset(skb, offset, to, copy);

		if ((len -= copy) == 0)
			return 0;
		offset += copy;
		to     += copy;
	}
        /*
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		int end;

		WARN_ON(start > offset + len);

		end = start + skb_shinfo(skb)->frags[i].size;
		if ((copy = end - offset) > 0) {
			u8 *vaddr;

			if (copy > len)
				copy = len;

			vaddr = kmap_skb_frag(&skb_shinfo(skb)->frags[i]);
			memcpy(to,
			       vaddr + skb_shinfo(skb)->frags[i].page_offset+
			       offset - start, copy);
			kunmap_skb_frag(vaddr);

			if ((len -= copy) == 0)
				return 0;
			offset += copy;
			to     += copy;
		}
		start = end;
	}

	skb_walk_frags(skb, frag_iter) {
		int end;

		WARN_ON(start > offset + len);

		end = start + frag_iter->len;
		if ((copy = end - offset) > 0) {
			if (copy > len)
				copy = len;
			if (skb_copy_bits(frag_iter, offset - start, to, copy))
				goto fault;
			if ((len -= copy) == 0)
				return 0;
			offset += copy;
			to     += copy;
		}
		start = end;
	}
        */
	if (!len)
		return 0;

fault:
	return -EFAULT;
}

__wsum skb_checksum(const struct sk_buff *skb, int offset,
                    int len, __wsum csum)
{
	int start = skb_headlen(skb);
	int copy = start - offset;

	/* Checksum header. */
	if (copy > 0) {
		if (copy > len)
			copy = len;
		csum = csum_partial(skb->data + offset, copy, csum);
		if ((len -= copy) == 0)
			return csum;
		offset += copy;
	}
        return csum;
}

static void skb_over_panic(struct sk_buff *skb, int sz, void *here)
{
	LOG_CRIT("skb_over_panic: text:%p len:%d put:%d head:%p "
		 "data:%p tail:%#lx end:%#lx dev:%s\n",
		 here, skb->len, sz, skb->head, skb->data,
		 (unsigned long)skb->tail, (unsigned long)skb->end,
		 skb->dev ? skb->dev->name : "<NULL>");
	exit(-1);
}

static void skb_under_panic(struct sk_buff *skb, int sz, void *here)
{
	LOG_CRIT("skb_under_panic: text:%p len:%d put:%d head:%p "
		 "data:%p tail:%#lx end:%#lx dev:%s\n",
		 here, skb->len, sz, skb->head, skb->data,
		 (unsigned long)skb->tail, (unsigned long)skb->end,
		 skb->dev ? skb->dev->name : "<NULL>");
	exit(-1);
}

unsigned char *skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *tmp = skb_tail_pointer(skb);
	SKB_LINEAR_ASSERT(skb);
	skb->tail += len;
	skb->len  += len;
	if (unlikely(skb->tail > skb->end))
		skb_over_panic(skb, len, __builtin_return_address(0));
	return tmp;
}

unsigned char *skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data -= len;
	skb->len  += len;
	if (unlikely(skb->data<skb->head))
		skb_under_panic(skb, len, __builtin_return_address(0));
	return skb->data;
}

unsigned char *skb_pull(struct sk_buff *skb, unsigned int len)
{
	return skb_pull_inline(skb, len);
}

void skb_trim(struct sk_buff *skb, unsigned int len)
{
	if (skb->len > len)
		__skb_trim(skb, len);
}
