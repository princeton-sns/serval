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
#include <libservalctrl/reactor.h>

/* define a thread-based version */

/* at this point, there's not much to gain
 * by using task (coroutine) based locking
 * since full mutex/semaphores are still needed
 * for multi-threaded use
 *
 * if the task library is used without
 * multi-threading, then it mightmake sense
 * to use task-based locks
 */
typedef pthread_mutex_t task_mutex_t;
typedef pthread_rwlock_t task_rwlock_t;

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

typedef unsigned long task_handle_t;

typedef struct task_cond {
    struct list_head wait_queue;
    unsigned int wait_count;
    pthread_mutex_t lock;
} task_cond_t;

int task_libinit(void);
void task_libfini(void);

int task_cond_init(task_cond_t *cond);
int task_cond_destroy(task_cond_t *cond);
int task_cond_wait(task_cond_t *cond, task_mutex_t *mutex);
int task_cond_notify(task_cond_t *cond);
int task_cond_notify_all(task_cond_t *cond);

int task_join(task_handle_t handle);
int task_kill(task_handle_t handle, int sig);

typedef void (*task_func_t) (void *data);

enum task_block_flags {
    FD_READ = RF_READ, 
    FD_WRITE = RF_WRITE, 
    FD_ERROR = RF_ERROR, 
    FD_ALL =  RF_ALL,
    TASK_QUIT = (1 << 3),
};

int task_add(task_handle_t *task, task_func_t tfunc, void *data);
int task_add_delayed(task_handle_t *handle, task_func_t tfunc, 
                     void *data, unsigned long millisecs);
int task_cancel(task_handle_t handle);
void task_yield(void);
int task_block(int fd, unsigned short flags);
void task_sleep(unsigned int ms);

#endif /* TASK_H_ */
