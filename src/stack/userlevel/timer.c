/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/debug.h>
#include <serval/lock.h>
#include <serval/timer.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <poll.h>

struct timer_internal {
	struct timespec expire_abs;
};

struct timer_list_head {
	unsigned long num_timers;
        struct timespec start_time;
	struct list_head head;
	pthread_mutex_t lock;
        int signal[2];
};

#if !defined(PER_THREAD_TIMER_LIST)
#define CLOCK CLOCK_REALTIME
static struct timer_list_head timer_list = {
        .num_timers = 0,
        .start_time = { 0, 0 },
        .head = { &timer_list.head, &timer_list.head },
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .signal = { -1, -1 },
};
#else
#define CLOCK CLOCK_THREAD_CPUTIME_ID
static pthread_key_t timer_list_head_key;
static pthread_once_t key_once = PTHREAD_ONCE_INIT;
#endif

int gettime(struct timespec *ts)
{
        int err = 0;

#if _POSIX_TIMERS > 0
        err = clock_gettime(CLOCK, ts);

	if (err == -1) {
		LOG_ERR("clock_gettime failed: %s\n", 
                        strerror(errno));
	}
#else
        struct timeval now;

        gettimeofday(&now, NULL);

        ts->tv_sec = now.tv_sec;
        ts->tv_nsec = now.tv_usec * 1000;
#endif
        return err;
}

/* This function gives a jiffies style time value indicating the
 * number of 10s of milliseconds since Serval was started */
unsigned long gettime_jiffies(void)
{
        struct timespec now;

        gettime(&now);

        timespec_sub(&now, &timer_list.start_time);

        return timespec_to_jiffies(&now);
}

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
                tl->entry.next = NULL;
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

static int __timer_list_signal_pending(struct timer_list_head *tlh)
{
        struct pollfd fds;
        int ret;

        fds.fd = tlh->signal[0];
        fds.events = POLLIN | POLLHUP;
        fds.revents = 0;

        ret = poll(&fds, 1, 0);

        if (ret == -1) {
                LOG_ERR("poll error: %s\n", strerror(errno));
        } else if (ret > 0) {
                ret = fds.revents;
        }

        return ret;
}

int timer_list_signal_pending(void)
{
        return  __timer_list_signal_pending(timer_list_get());
}

static int __timer_list_signal_lower(struct timer_list_head *tlh)
{
	ssize_t sz = 1;
	char r = 'r';

        while (sz > 0 && __timer_list_signal_pending(tlh) & POLLIN) {
                sz = read(tlh->signal[0], &r, 1);
	}

	return (int)sz;
}

int timer_list_signal_lower(void)
{
	return __timer_list_signal_lower(timer_list_get());
}

static int timer_list_signal_timer_change(struct timer_list_head *tlh)
{
        char w = 'w';
        
        if (tlh->signal[1] == -1)
                return -1;

        if (__timer_list_signal_pending(tlh))
                return 0;

	return (int)write(tlh->signal[1], &w, 1);
}

int timer_list_get_next_timeout(struct timespec *timeout, int signal[2])
{
	struct timer_list_head *tlh = timer_list_get_locked();
	struct timer_list *timer;
	struct timespec now = { 0, 0 };

	if (!tlh)
		return -1;
	
        memcpy(tlh->signal, signal, sizeof(int)*2);

        /* Lower any pending signals */
        __timer_list_signal_lower(tlh);

	if (list_empty(&tlh->head)) {
		timer_list_unlock(tlh);
		return 0;
	}

	timer = list_first_entry(&tlh->head, struct timer_list, entry);

        gettime(&now);
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
        timer->entry.next = NULL;

	timer_list_unlock(tlh);

	/* Call timer function, passing the data */
        if (timer->function) {
                timer->function(timer->data); 
        } else {
                LOG_WARN("timer function is NULL\n");
        }
        
	return 1;
}

#if defined(PER_THREAD_TIMER_LIST)
static void make_keys(void)
{
	pthread_key_create(&timer_list_head_key, timer_list_head_destructor);
}

int timer_list_per_thread_init()
{
	struct timer_list_head *tlh;
	int ret;      

	pthread_once(&key_once, make_keys);	

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
        gettime(&tlh->start_time);

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
#else
/* !PER_THREAD */

#if defined(__GNUC__) || defined(__BIONIC__)
/* Make this function be auto-called on load */
__attribute__((constructor))
#else
#warning "timer_list_init() will not be auto called on load!"
#endif
void timer_list_init(void)
{
        gettime(&timer_list.start_time);
}
#endif

void init_timer(struct timer_list *timer)
{
        memset(timer, 0, sizeof(*timer));
        timer->entry.next = NULL;
}

void add_timer(struct timer_list *timer)
{
	BUG_ON(timer_pending(timer));
	mod_timer(timer, timer->expires);
}

int del_timer(struct timer_list *timer)
{
	struct timer_list_head *tlh = timer_list_get_locked();
	int signal_change = 0;

	if (!tlh)
		return -1;
	
        if (timer->entry.next == NULL)
                return 0;

	if (timer->entry.prev == &tlh->head) {
                /* Entry is first in queue, must signal change */
                signal_change = 1;
        } 

        list_del(&timer->entry);
        timer->entry.next = NULL;

	timer_list_unlock(tlh);

        if (signal_change) 
                timer_list_signal_timer_change(tlh);

	return 1;
}

int mod_timer(struct timer_list *timer, unsigned long expires)
{
	struct timer_list_head *tlh = timer_list_get_locked();
        unsigned long delta;
        int ret = 0;

	if (!tlh)
		return -1;

        if (timer_pending(timer) && 
            timer->expires == expires) {
                timer_list_unlock(tlh);
                return 1;
        }

	if (timer_pending(timer)) {
		list_del(&timer->entry);
                ret = 1;
        }

        gettime(&timer->expires_abs);
	timer->expires = expires;
        delta = expires - jiffies;
	timespec_add_nsec(&timer->expires_abs, 
                          jiffies_to_nsecs(delta)); 
        /*
        LOG_DBG("timer[expires=%lu delta=%lu"
                " tv_sec=%ld tv_nsec=%ld]\n",
                expires, delta,
                timer->expires_abs.tv_sec, 
                timer->expires_abs.tv_nsec);
        */
	if (list_empty(&tlh->head)) {
		list_add(&timer->entry, &tlh->head);
                timer_list_signal_timer_change(tlh);
	} else {
		unsigned int num = 0;
		struct timer_list *tl;
		/* Find place where to insert based on absolute time */
		list_for_each_entry(tl, &tlh->head, entry) {
			if (timespec_lt(&timer->expires_abs, 
                                        &tl->expires_abs))
                                break;
			num++;
		}

                list_add_tail(&timer->entry, &tl->entry);

		if (timer->entry.prev == &tlh->head) {
                        /* Inserted first in queue, so we must signal
                         * that the timeout has changed. */
                        timer_list_signal_timer_change(tlh);
                } 
	}
       
	timer_list_unlock(tlh);

	return ret;
}

int mod_timer_pending(struct timer_list *timer, unsigned long expires)
{
	return 0;
}

int mod_timer_pinned(struct timer_list *timer, unsigned long expires)
{
	return 0;
}
