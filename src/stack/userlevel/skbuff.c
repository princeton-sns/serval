#include <string.h>
#include <sys/uio.h>
#include <scaffold/debug.h>
#include <scaffold/platform.h>
#include <scaffold/lock.h>
#include <scaffold/skbuff.h>

static void skb_release_head_state(struct sk_buff *skb)
{
	/* Release state associated with head */
}

static void skb_release_data(struct sk_buff *skb)
{
	if (!skb->cloned ||
	    !atomic_sub_return(/*skb->nohdr ? (1 << SKB_DATAREF_SHIFT) + 1 : */1,
			       &skb_shinfo(skb)->dataref)) {
		
		free(skb->head);
	}
	/* Free our fake device */
	if (skb->dev)
		free(skb->dev);
}

/* Free everything but the sk_buff shell. */
static void skb_release_all(struct sk_buff *skb)
{
	skb_release_head_state(skb);
	skb_release_data(skb);
}

void __free_skb(struct sk_buff *skb)
{
	skb_release_all(skb);
	free(skb);
}

void free_skb(struct sk_buff *skb)
{
	if (likely(!atomic_dec_and_test(&skb->users)))
		return;

	__free_skb(skb);
}

int skb_alloc_and_set_netdevice(struct sk_buff *skb, int ifindex, const char *name)
{
	struct net_device *dev;
	
	dev = (struct net_device *)malloc(sizeof(struct net_device));

	if (!dev)
		return -ENOMEM;
	
	dev->ifindex = ifindex;
	strcpy(dev->name, name);

	if (skb->dev)
		free(skb->dev);
	
	skb->dev = dev;

	return 0;
}

struct sk_buff *alloc_skb(unsigned int size)
{
	unsigned char *data;
	struct sk_buff *skb;
	struct skb_shared_info *shinfo;
	
	skb = (struct sk_buff *)malloc(sizeof(struct sk_buff));

	if (!skb)
		return NULL;

	data = (unsigned char *)malloc(size + sizeof(struct skb_shared_info));

	if (!data)
		goto nodata;

	/*
	 * Only clear those fields we need to clear, not those that we will
	 * actually initialise below. Hence, don't put any more fields after
	 * the tail pointer in struct sk_buff!
	 */
	memset(skb, 0, offsetof(struct sk_buff, tail));
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

	return skb;
nodata:
	free(skb);
	return NULL;
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
		free_skb(skb);
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
void skb_insert(struct sk_buff *old, struct sk_buff *newsk, struct sk_buff_head *list)
{
	spin_lock(&list->lock);
	__skb_insert(newsk, old->prev, old, list);
	spin_unlock(&list->lock);
}

int skb_copy_datagram_iovec(const struct sk_buff *from,
                            int offset, struct iovec *to,
                            int size)
{
	return 0;
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
