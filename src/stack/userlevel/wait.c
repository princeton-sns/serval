/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#define _GNU_SOURCE /* For ppoll to be defined */
#include <serval/wait.h>
#include <serval/timer.h>
#include <serval/debug.h>
#include <userlevel/client.h>

#include <pthread.h>
#include <sys/select.h>
#include <poll.h>
#include <unistd.h>

static pthread_key_t wq_key;
static pthread_key_t w_key;
static pthread_once_t key_once = PTHREAD_ONCE_INIT;

#define MAX(x, y) (x >= y ? x : y)

void init_waitqueue_head(wait_queue_head_t *q)
{
	pthread_mutex_init(&q->lock, NULL);
	INIT_LIST_HEAD(&q->thread_list);
}

void destroy_waitqueue_head(wait_queue_head_t *q)
{
        pthread_mutex_destroy(&q->lock);
}

void init_wait(wait_queue_t *w)
{        
	pthread_mutex_init(&w->lock, NULL);
	if (pipe(w->pipefd) == -1) {
                LOG_ERR("pipe: %s\n", strerror(errno));
        }
	INIT_LIST_HEAD(&w->thread_list);
}

void destroy_wait(wait_queue_t *w)
{
        pthread_mutex_destroy(&w->lock);
        if (w->pipefd[0] > 0)
                close(w->pipefd[0]);
        if (w->pipefd[1] > 0)
                close(w->pipefd[1]);
}

int default_wake_function(wait_queue_t *curr, unsigned mode, 
                          int wake_flags, void *key)
{
        uint8_t sig = 1;
        int ret;

        LOG_DBG("Waking up sleepers!\n");
        
        if (curr->pipefd[1] == -1) {
                LOG_ERR("pipefd[1] == -1\n");
                return -1;
        }

        ret = write(curr->pipefd[1], &sig, sizeof(sig));
        
        if (ret < 0) {
                LOG_ERR("Could not write in signal to pipe: %u\n", 
                        curr->pipefd[1]);
        }

	return ret;
}

/* 
   schedule_timeout:

   Assume we are using microsecond precision.

   As in kernel, returns the remaining time, never negative.
*/
long schedule_timeout(long timeo)
{        
        wait_queue_head_t *q = 
                (wait_queue_head_t *)pthread_getspecific(wq_key);
        wait_queue_t *w = (wait_queue_t *)pthread_getspecific(w_key);
        struct client *c = client_get_current();
        struct timespec now = { 0, 0 }, later = { 0, 0 };
        struct pollfd fds[3];
        int ret = 0;

        if (!q || !w || !c) {
                LOG_ERR("No client or wait queue!\n");
                return timeo;
        }

        gettime(&now);

        fds[0].fd = w->pipefd[0];
        fds[0].events = POLLERR | POLLIN;
        fds[1].fd = client_get_signalfd(c);
        fds[1].events = POLLERR | POLLIN;
        fds[2].fd = client_get_sockfd(c);
        fds[2].events = POLLERR | POLLHUP;

        if (timeo == MAX_SCHEDULE_TIMEOUT) {
                ret = ppoll(fds, 3, NULL, NULL);
        } else {
                struct timespec timeout = { 0, 0 };
                timespec_add_nsec(&timeout, jiffies_to_nsecs(timeo));
                ret = ppoll(fds, 3, &timeout, NULL);
        }
        
        if (ret == -1) {
                LOG_ERR("poll error: %s\n", strerror(errno));
        } else if (ret == 0) {
                timeo = 0;
        } else if (timeo != MAX_SCHEDULE_TIMEOUT) {
                /*
                  On Linux, pselect returns the time not slept in the
                  timeout. Not sure how ppoll works. In any case, this
                  is not portable.
                */
                gettime(&later);
                
                timespec_sub(&later, &now);

                if (later.tv_sec < 0 || 
                    (later.tv_sec == 0 && (later.tv_nsec < 999)))
                        timeo = 0;
                else {
                        timeo = timespec_to_jiffies(&later);
                }
        }

        return timeo;
}

static void make_keys(void)
{
	pthread_key_create(&wq_key, NULL);
	pthread_key_create(&w_key, NULL);
}

void pre_add_wait_queue(wait_queue_head_t *q, wait_queue_t *wait)
{
        int ret;
        
	pthread_once(&key_once, make_keys);
        
        /*
          if (pthread_getspecific(wq_key)) {
          LOG_ERR("Wait queue key already set\n");
          return;
          }
        */
	ret = pthread_setspecific(wq_key, q);
        
	if (ret != 0) {
                LOG_ERR("Could not set wait queue key\n");
                return;
        }

	ret = pthread_setspecific(w_key, wait);
        
	if (ret != 0) {
                LOG_ERR("Could not set wait queue key\n");
                return;
        }
}

void __add_wait_queue(wait_queue_head_t *head, wait_queue_t *new)
{
        pre_add_wait_queue(head, new);
	list_add(&new->thread_list, &head->thread_list);
}

void __add_wait_queue_tail(wait_queue_head_t *head,
                           wait_queue_t *new)
{
        pre_add_wait_queue(head, new);
	list_add_tail(&new->thread_list, &head->thread_list);
}

int autoremove_wake_function(wait_queue_t *wait, unsigned mode, 
                             int sync, void *key)
{
	int ret = default_wake_function(wait, mode, sync, key);

	if (ret)
		list_del_init(&wait->thread_list);
	return ret;
}

void prepare_to_wait(wait_queue_head_t *q, wait_queue_t *wait, int state)
{
	wait->flags &= ~WQ_FLAG_EXCLUSIVE;
	pthread_mutex_lock(&q->lock);
	if (list_empty(&wait->thread_list))
		__add_wait_queue(q, wait);
	/* set_current_state(state); */
	pthread_mutex_unlock(&q->lock);
}

void prepare_to_wait_exclusive(wait_queue_head_t *q, wait_queue_t *wait, 
                               int state)
{
	wait->flags |= WQ_FLAG_EXCLUSIVE;
	pthread_mutex_lock(&q->lock);
	if (list_empty(&wait->thread_list))
		__add_wait_queue_tail(q, wait);
	/* set_current_state(state); */
	pthread_mutex_unlock(&q->lock);
}
void finish_wait(wait_queue_head_t *q, wait_queue_t *wait)
{
	/* __set_current_state(TASK_RUNNING); */
        
	if (!list_empty(&wait->thread_list)) {
                pthread_mutex_lock(&q->lock);
		list_del_init(&wait->thread_list);
                pthread_mutex_unlock(&q->lock);
	}
        destroy_wait(wait);
}

void add_wait_queue(wait_queue_head_t *q, wait_queue_t *wait)
{
	wait->flags &= ~WQ_FLAG_EXCLUSIVE;
	pthread_mutex_lock(&q->lock);
	__add_wait_queue(q, wait);
	pthread_mutex_unlock(&q->lock);
}

void add_wait_queue_exclusive(wait_queue_head_t *q, wait_queue_t *wait)
{
	wait->flags |= WQ_FLAG_EXCLUSIVE;
	pthread_mutex_lock(&q->lock);
	__add_wait_queue_tail(q, wait);
	pthread_mutex_unlock(&q->lock);
}

void remove_wait_queue(wait_queue_head_t *q, wait_queue_t *wait)
{
        pthread_setspecific(wq_key, NULL);
	pthread_setspecific(w_key, NULL);

	pthread_mutex_lock(&q->lock);
	__remove_wait_queue(q, wait);
	pthread_mutex_unlock(&q->lock);
}

void __wake_up_common(wait_queue_head_t *q, unsigned int mode,
                      int nr_exclusive, int wake_flags, void *key)
{
	wait_queue_t *curr, *next;

	list_for_each_entry_safe(curr, next, &q->thread_list, thread_list) {
		unsigned flags = curr->flags;
		if (curr->func(curr, mode, wake_flags, key) &&
                    (flags & WQ_FLAG_EXCLUSIVE) && !--nr_exclusive)
			break;
	}
}

void __wake_up(wait_queue_head_t *q, unsigned int mode,
               int nr_exclusive, void *key)
{
	pthread_mutex_lock(&q->lock);
	__wake_up_common(q, mode, nr_exclusive, 0, key);
	pthread_mutex_unlock(&q->lock);
}

/*
 * Same as __wake_up but called with the spinlock in wait_queue_head_t held.
 */
void __wake_up_locked(wait_queue_head_t *q, unsigned int mode)
{
        __wake_up_common(q, mode, 1, 0, NULL);
}

void __wake_up_locked_key(wait_queue_head_t *q, unsigned int mode, void *key)
{
        __wake_up_common(q, mode, 1, 0, key);
}

/**
 * __wake_up_sync_key - wake up threads blocked on a waitqueue.
 * @q: the waitqueue
 * @mode: which threads
 * @nr_exclusive: how many wake-one or wake-many threads to wake up
 * @key: opaque value to be passed to wakeup targets
 *
 * The sync wakeup differs that the waker knows that it will schedule
 * away soon, so while the target thread will be woken up, it will not
 * be migrated to another CPU - ie. the two threads are 'synchronized'
 * with each other. This can prevent needless bouncing between CPUs.
 *
 * On UP it can prevent extra preemption.
 *
 * It may be assumed that this function implies a write memory barrier before
 * changing the task state if and only if any tasks are woken up.
 */
void __wake_up_sync_key(wait_queue_head_t *q, unsigned int mode,
                        int nr_exclusive, void *key)
{
        int wake_flags = 0; /* WF_SYNC; */

        if (unlikely(!q))
                return;

        if (unlikely(!nr_exclusive))
                wake_flags = 0;

        pthread_mutex_lock(&q->lock);
        __wake_up_common(q, mode, nr_exclusive, wake_flags, key);
        pthread_mutex_unlock(&q->lock);
}

/*
 * __wake_up_sync - see __wake_up_sync_key()
 */
void __wake_up_sync(wait_queue_head_t *q, unsigned int mode, int nr_exclusive)
{
        __wake_up_sync_key(q, mode, nr_exclusive, NULL);
}

int signal_pending(struct task_struct *task)
{
        int ret = 0;
        struct pollfd fds[2];
        struct client *c = client_get_current();

        if (!c) {
                LOG_ERR("bad client\n");
                return -1;
        }
        
        fds[0].fd = client_get_signalfd(c);
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        fds[1].fd = client_get_sockfd(c);
        fds[1].events = POLLHUP;
        fds[1].revents = 0;

        ret = poll(fds, 2, 0);

        if (ret == -1) {
                LOG_ERR("select error: %s\n", strerror(errno));
        } else if (ret == 0) {
                
        } else {
                /* 
                   Probably not necessary to reset signals here
                   since it probably means the client should exit
                   or the signals are reset somewhere else.
                */

        }

        return ret > 0;
}
