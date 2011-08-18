/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * task.h
 *
 *  Created on: Feb 16, 2011
 *      Author: daveds
 */

#ifndef TASK_H_
#define TASK_H_

#include <stdint.h>
#include <sys/types.h>
#include <sys/time.h>
//#include "timeval.h"
#include <signal.h>
#include <string.h>
#include <sys/errno.h>
#include <time.h>
#include <stdint.h>
#include <pthread.h>
/*should move task_cond def to a private header file*/
#include <serval/list.h>

/* define a thread-based version */

typedef long int task_handle_t;
/* at this point, there's not much to gain
 * by using task (coroutine) based locking
 * since full mutex/semaphores are still needed
 * for multi-threaded use
 *
 * if the task library is used without
 * multi-threading, then it mightmake sense
 * to use task-based locks
 */

/*
 typedef struct task_mutex_t task_mutex;
 typedef struct task_rwlock_t task_rwlock;

 int task_mutex_init(task_mutex* mutex);
 int task_mutex_destroy(task_mutex* mutex);
 int task_mutex_lock(task_mutex* mutex);
 int task_mutex_unlock(task_mutex* mutex);
 int task_mutex_trylock(task_mutex* mutex);

 int task_rwlock_init(task_rwlock* rwlock);
 int task_rwlock_destroy(task_rwlock* rwlock);
 int task_rwlock_rdlock(task_rwlock* rwlock);
 int task_rwlock_wrlock(task_rwlock* rwlock);
 int task_rwlock_unlock(task_rwlock* rwlock);
 int task_rwlock_tryrdlock(task_rwlock* rwlock);
 int task_rwlock_trywrlock(task_rwlock* rwlock);
 */

typedef pthread_mutex_t task_mutex;
typedef pthread_rwlock_t task_rwlock;

#define task_mutex_init(mutex) pthread_mutex_init(mutex, NULL)
#define task_mutex_destroy(mutex) pthread_mutex_destroy(mutex)
#define task_mutex_lock(mutex) pthread_mutex_lock(mutex)
#define task_mutex_unlock(mutex) pthread_mutex_unlock(mutex)
#define task_mutex_trylock(mutex) pthread_mutex_trylock(mutex);

#define task_rwlock_init(rwlock) pthread_rwlock_init(rwlock, NULL)
#define task_rwlock_destroy(rwlock) pthread_rwlock_destroy(rwlock)
#define task_rwlock_rdlock(rwlock) pthread_rwlock_rdlock(rwlock)
#define task_rwlock_wrlock(rwlock) pthread_rwlock_wrlock(rwlock)
#define task_rwlock_unlock(rwlock) pthread_rwlock_unlock(rwlock)
#define task_rwlock_tryrdlock(rwlock) pthread_rwlock_tryrdlock(rwlock)
#define task_rwlock_trywrlock(rwlock) pthread_rwlock_trywrlock(rwlock)

#define TASK_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

/* a task cond can make a difference by freeing the
 * thread from waiting
 */

struct task_cond_t {
    struct list_head wait_queue;
    uint32_t wait_count;
};

typedef struct task_cond_t task_cond;

void initialize_tasks(int threads);
void finalize_tasks();

int task_cond_init(task_cond * cond);
int task_cond_destroy(task_cond * cond);
int task_cond_wait(task_cond * cond, task_mutex * mutex);
int task_cond_notify(task_cond * cond);
int task_cond_notify_all(task_cond * cond);

int task_join(task_handle_t handle);
int task_kill(task_handle_t handle, int sig);

typedef void (*task_func) (void *data);

/*who owns/is responsible for the data? TODO */
task_handle_t task_add(void *data, task_func tfunc);
int task_remove(task_handle_t handle);
int is_valid_task(task_handle_t handle);
int task_count();

/*perhaps a simple recurring task should be added as well*/
task_handle_t add_timer_task(void *data, task_func tfunc, struct timeval *tval);
int remove_timer_task(task_handle_t handle);
int is_valid_timer_task(task_handle_t handle);

enum task_block {
    FD_READ = 1 << 0, FD_WRITE = 1 << 1, FD_ERROR = 1 << 2, FD_ALL = 1 << 3
};

int task_free_count();
void task_yield();
void task_block(int fd, int flags);
task_handle_t add_task_block(int fd, int flags, void *data, task_func tfunc);
task_handle_t task_unblock(int fd, int flags);
void task_sleep(int ms);

#endif				/* TASK_H_ */
