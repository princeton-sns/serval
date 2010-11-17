/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/debug.h>
#include <scaffold/lock.h>
#include <scaffold/timer.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

struct timer_internal {
	struct timespec expire_abs;
};

struct timer_list_head {
	unsigned long num_timers;
	struct list_head head;
	pthread_mutex_t lock;
};

#if !defined(PER_THREAD_TIMER_LIST)
static struct timer_list_head timer_list = {
        .num_timers = 0,
        .head = { &timer_list.head, &timer_list.head },
        .lock = PTHREAD_MUTEX_INITIALIZER
};
#else
static pthread_key_t timer_list_head_key;
static pthread_once_t key_once = PTHREAD_ONCE_INIT;
#endif

#define CLOCK CLOCK_THREAD_CPUTIME_ID

static inline int timer_list_lock(struct timer_list_head *tlh)
{
	return pthread_mutex_lock(&tlh->lock);
}

static inline int timer_list_unlock(struct timer_list_head *tlh)
{
	return pthread_mutex_unlock(&tlh->lock);
}

#if defined(PER_THREAD_TIMER_LIST)
static void timer_list_head_destructor(void *arg)
{
	struct timer_list_head *tlh = (struct timer_list_head *)arg;
	
	while (!list_empty(&tlh->head)) {
		struct timer_list *tl = list_first_entry(&tlh->head, 
							 struct timer_list, 
							 entry);
		list_del(&tl->entry);
	}

	pthread_mutex_destroy(&tlh->lock);

	free(tlh);
}
#endif

static inline struct timer_list_head *timer_list_get(void)
{
#if defined(PER_THREAD_TIMER_LIST)
	return (struct timer_list_head *)pthread_getspecific(timer_list_head_key);
#else
        return &timer_list;
#endif
}

static inline struct timer_list_head *timer_list_get_locked(void)
{
	struct timer_list_head *tlh = timer_list_get();

	if (!tlh)
		return NULL;

	if (timer_list_lock(tlh) == -1)
		return NULL;
	
	return tlh;
}

int timer_list_get_next_timeout(struct timespec *timeout)
{
	struct timer_list_head *tlh = timer_list_get_locked();
	struct timer_list *timer;
	struct timespec now;

	if (!tlh)
		return -1;
	
	if (list_empty(&tlh->head)) {
		timer_list_unlock(tlh);
		return 0;
	}

	timer = list_first_entry(&tlh->head, struct timer_list, entry);

	if (clock_gettime(CLOCK, &now) == -1) {
		LOG_DBG("clock_gettime failed: %s\n", strerror(errno));
		timer_list_unlock(tlh);
		return -1;
	}
	memcpy(timeout, &timer->expires_abs, sizeof(*timeout));
	timespec_sub(timeout, &now);
	timer_list_unlock(tlh);

	return 1;
}

int timer_list_handle_timeout(void)
{
	struct timer_list_head *tlh = timer_list_get_locked();
	struct timer_list *timer;

	if (!tlh)
		return -1;
	
	if (list_empty(&tlh->head)) {
		timer_list_unlock(tlh);
		return 0;
	}
	
	timer = list_first_entry(&tlh->head, struct timer_list, entry);
	
	list_del(&timer->entry);

	timer_list_unlock(tlh);

	/* Call timer function, passing the data */
	timer->function(timer->data);

	return 1;
}

#if defined(PER_THREAD_TIMER_LIST)
static void make_list_key(void)
{
	pthread_key_create(&timer_list_head_key, timer_list_head_destructor);
}

int timer_list_per_thread_init()
{
	struct timer_list_head *tlh;
	int ret;      

	pthread_once(&key_once, make_list_key);	

	/* Check if init was already done for this thread */
	if (timer_list_get())
		return 0;

	tlh = (struct timer_list_head *)malloc(sizeof(*tlh));

	if (!tlh)
		return -1;
	
	ret = pthread_setspecific(timer_list_head_key, tlh);

	if (ret != 0) {
		free(tlh);
		return -1;
	}

	memset(tlh, 0, sizeof(*tlh));
	INIT_LIST_HEAD(&tlh->head);
	tlh->num_timers = 0;
	/* Make mutex recursive */
#if RECURSIVE_MUTEX
        { 
                pthread_mutexattr_t attr;
                pthread_mutexattr_init(&attr);
                pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
                pthread_mutex_init(&tlh->lock, &attr);
                pthread_mutexattr_destroy(&attr);
        }
#else
        pthread_mutex_init(&tlh->lock, NULL);
#endif
	return 1;
}
#endif

void init_timer(struct timer_list *timer)
{
        memset(timer, 0, sizeof(*timer));
        INIT_LIST_HEAD(&timer->entry);
}

void add_timer(struct timer_list *timer)
{
	BUG_ON(timer_pending(timer));
	mod_timer(timer, timer->expires);
}

int del_timer(struct timer_list *timer)
{
	struct timer_list_head *tlh = timer_list_get_locked();
	
	if (!tlh)
		return -1;
	
	timer_list_unlock(tlh);

	return 0;
}

int mod_timer(struct timer_list *timer, unsigned long expires)
{
	struct timer_list_head *tlh = timer_list_get_locked();
	struct timespec usecs;

	if (!tlh)
		return -1;
	
	if (timer_pending(timer))
		list_del(&timer->entry);

	if (clock_gettime(CLOCK, &timer->expires_abs) == -1) {
		LOG_DBG("clock_gettime failed: %s\n", strerror(errno));
		timer_list_unlock(tlh);
		return -1;
	}
	

	/* Set timeout, both relative and absolute. */
	usecs.tv_sec = expires / 1000000;
	usecs.tv_nsec = (long)(expires - (usecs.tv_sec * 1000000)) * 1000;
	timer->expires = expires;
	timespec_add(&timer->expires_abs, &usecs);

	if (list_empty(&tlh->head)) {
		list_add(&timer->entry, &tlh->head);
	} else {
		unsigned int num = 0;
		struct timer_list *tl = NULL;
		/* Find place where to insert based on absolute time */
		list_for_each_entry(tl, &tlh->head, entry) {
			if (timespec_lt(&timer->expires_abs, &tl->expires_abs)) {
				list_add_tail(&timer->entry, &tl->entry);
				goto insert_done;
			}
			num++;
		}
		/* if (tl == &tlh->head) */
		list_add_tail(&timer->entry, &tlh->head);
	}
	
insert_done:
	timer_list_unlock(tlh);

	return 0;
}

int mod_timer_pending(struct timer_list *timer, unsigned long expires)
{
	return 0;
}

int mod_timer_pinned(struct timer_list *timer, unsigned long expires)
{
	return 0;
}
