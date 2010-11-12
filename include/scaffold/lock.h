/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _LOCK_H
#define _LOCK_H

#if defined(__KERNEL__)
#include <linux/spinlock.h>
#else
#include <pthread.h>

typedef pthread_mutex_t spinlock_t;

#define spin_lock_init(x) pthread_mutex_init(x, NULL)
#define spin_lock_init_recursive(x) {                              \
	pthread_mutexattr_t attr;                                  \
	pthread_mutexattr_init(&attr);                             \
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE); \
	pthread_mutex_init(&mutex, &attr);                         \
	pthread_mutexattr_destroy(&attr); }
#define spin_lock(x) pthread_mutex_lock(x)
#define spin_trylock(x) pthread_mutex_trylock(x)
#define spin_unlock(x) pthread_mutex_unlock(x)

#define spin_lock_bh(x) pthread_mutex_lock(x)
#define spin_trylock_bh(x) pthread_mutex_trylock(x)
#define spin_unlock_bh(x) pthread_mutex_unlock(x)

typedef pthread_mutex_t rwlock_t;

#define rwlock_init(x) pthread_mutex_init(x, NULL)
#define rwlock_lock(x) pthread_mutex_lock(x)
#define rwlock_trylock(x) pthread_mutex_trylock(x)
#define rwlock_unlock(x) pthread_mutex_unlock(x)

#define rwlock_trylock_bh(x) pthread_mutex_trylock(x)
#define rwlock_unlock_bh(x) pthread_mutex_unlock(x)

#endif /* __KERNEL__ */

#endif /* _LOCK_H */
