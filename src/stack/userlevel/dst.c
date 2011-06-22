/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/platform.h>
#include <serval/atomic.h>
#include <serval/skbuff.h>
#include <serval/lock.h>
#include <serval/dst.h>
#include <serval/netdevice.h>
#include <pthread.h>

int dst_discard(struct sk_buff *skb)
{
	kfree_skb(skb);
	return 0;
}

void *dst_alloc(struct dst_ops *ops)
{
	struct dst_entry *dst;
        /*
	if (ops->gc && atomic_read(&ops->entries) > ops->gc_thresh) {
		if (ops->gc(ops))
			return NULL;
	}
        */
        dst = malloc(ops->kmem_cachep->size);
        
	if (!dst)
		return NULL;

	atomic_set(&dst->__refcnt, 0);
	dst->ops = ops;
	//dst->lastuse = jiffies
	dst->path = dst;
	dst->input = dst->output = dst_discard;
	atomic_inc(&ops->entries);

	return dst;
}

static void ___dst_free(struct dst_entry *dst)
{
	/* The first case (dev==NULL) is required, when
	   protocol module is unloaded.
	 */
	if (dst->dev == NULL || !(dst->dev->flags&IFF_UP))
		dst->input = dst->output = dst_discard;
	dst->obsolete = 2;
}

void __dst_free(struct dst_entry *dst)
{
	//spin_lock_bh(&dst_garbage.lock);
	___dst_free(dst);
        /**
	dst->next = dst_garbage.list;
	dst_garbage.list = dst;
	if (dst_garbage.timer_inc > DST_GC_INC) {
		dst_garbage.timer_inc = DST_GC_INC;
		dst_garbage.timer_expires = DST_GC_MIN;
		cancel_delayed_work(&dst_gc_work);
		schedule_delayed_work(&dst_gc_work, dst_garbage.timer_expires);
	}
	spin_unlock_bh(&dst_garbage.lock);
        */
}

struct dst_entry *dst_destroy(struct dst_entry *dst)
{
	/*
          struct dst_entry *child;

          child = dst->child;
        */
	atomic_dec(&dst->ops->entries);

	if (dst->ops->destroy)
		dst->ops->destroy(dst);
	if (dst->dev)
		dev_put(dst->dev);

        free(dst);
#if 0
	dst = child;
	if (dst) {
		int nohash = dst->flags & DST_NOHASH;

		if (atomic_dec_and_test(&dst->__refcnt)) {
			/* We were real parent of this dst, so kill child. */
			if (nohash)
				goto again;
		} else {
			/* Child is still referenced, return it for freeing. */
			if (nohash)
				return dst;
			/* Child is still in his hash table */
		}
	}
#endif
	return NULL;
}

void dst_release(struct dst_entry *dst)
{
	if (dst) {
		/* int newrefcnt;
                   newrefcnt = */
                atomic_dec_return(&dst->__refcnt);
	}
}

/* Dirty hack. We did it in 2.2 (in __dst_free),
 * we have _very_ good reasons not to repeat
 * this mistake in 2.3, but we have no choice
 * now. _It_ _is_ _explicit_ _deliberate_
 * _race_ _condition_.
 *
 * Commented and originally written by Alexey.
 */
/*
static void dst_ifdown(struct dst_entry *dst, struct net_device *dev,
		       int unregister)
{
	if (dst->ops->ifdown)
		dst->ops->ifdown(dst, dev, unregister);

	if (dev != dst->dev)
		return;

	if (!unregister) {
		dst->input = dst->output = dst_discard;
	} else {
		dst->dev = dev_net(dst->dev)->loopback_dev;
		dev_hold(dst->dev);
		dev_put(dev);
		if (dst->neighbour && dst->neighbour->dev == dev) {
			dst->neighbour->dev = dst->dev;
			dev_hold(dst->dev);
			dev_put(dev);
		}
	}
}
*/
