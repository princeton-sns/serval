/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _ATOMIC_H_
#define _ATOMIC_H_

#if defined(__linux__) && defined(__KERNEL__)
#include <linux/kernel.h>
#else
#if defined(__linux__) ||      \
        defined(__OpenBSD__) || \
        defined(__FreeBSD__) || \
        defined(__APPLE__)
#if !defined(__BIONIC__)
#define HAVE_GCC_ATOMICS 1
#endif
#endif

#if defined(HAVE_GCC_ATOMICS)

#define ATOMIC_INIT(i)	{ (i) }

typedef struct {
	int value;
} atomic_t;

static inline int atomic_read(const atomic_t *v)
{
	return __sync_add_and_fetch(&((atomic_t *)v)->value, 0);
}

static inline int atomic_add_return(int i, atomic_t *v)
{
	return __sync_add_and_fetch(&v->value, i);
}

static inline int atomic_sub_return(int i, atomic_t *v)
{
	return __sync_sub_and_fetch(&v->value, i);
}

static inline int atomic_set(atomic_t *v, int i)
{
        return __sync_val_compare_and_swap(&v->value, atomic_read(v), i);
}

#elif defined(__BIONIC__)
#include <sys/atomics.h>
typedef struct {
	int value;
} atomic_t;

#define ATOMIC_INIT(i) { (i) }

#define atomic_read(v) *((volatile int *)&(v)->value)

static inline int atomic_add_return(int i, atomic_t *v)
{
        int old;
        
        do {
                old = *(volatile int *)&v->value;
        }
        while (__atomic_cmpxchg(old, old+i, (volatile int*)&v->value));
        
        return old+i;
}

static inline int atomic_sub_return(int i, atomic_t *v)
{
        int old;
        do {
                old = *(volatile int *)&v->value;
        }
        while (__atomic_cmpxchg(old, old-i, (volatile int*)&v->value));

	return old-i;
}

#define atomic_set(v, i) __atomic_swap(i, &(v)->value)

#else /* GENERIC */
#include <pthread.h>

#define ATOMIC_INIT(i) { (i) , PTHREAD_MUTEX_INITIALIZER }

typedef struct {
	int value;
        pthread_mutex_t mutex;
} atomic_t;

#warning "using generic atomic.h, consider implementing atomics for this platform"

static inline int atomic_read(const atomic_t *v)
{
        int val;        
        pthread_mutex_lock(&((atomic_t *)v)->mutex);
        val = ((atomic_t *)v)->value;
        pthread_mutex_unlock(&((atomic_t *)v)->mutex);
	return val;
}

static inline int atomic_add_return(int i, atomic_t *v)
{
        int val;        
        pthread_mutex_lock(&v->mutex);
        val = ++v->value;
        pthread_mutex_unlock(&v->mutex);
	return val;
}

static inline int atomic_sub_return(int i, atomic_t *v)
{
        int val;        
        pthread_mutex_lock(&v->mutex);
        val = --v->value;
        pthread_mutex_unlock(&v->mutex);
	return val;
}

/* Probably this is ok for most platforms */
#define atomic_set(v, i) (((v)->value) = (i))


#endif /* __GLIBC__ */

static inline int atomic_add_negative(int i, atomic_t *v)
{
        return atomic_add_return(i, v) < 0;
}

static inline void atomic_add(int i, atomic_t *v)
{
        atomic_add_return(i, v);
}

static inline void atomic_sub(int i, atomic_t *v)
{
        atomic_sub_return(i, v);
}

static inline void atomic_inc(atomic_t *v)
{
        atomic_add_return(1, v);
}

static inline void atomic_dec(atomic_t *v)
{
        atomic_sub_return(1, v);
}

#define atomic_dec_return(v)            atomic_sub_return(1, (v))
#define atomic_inc_return(v)            atomic_add_return(1, (v))

#define atomic_sub_and_test(i, v)       (atomic_sub_return((i), (v)) == 0)
#define atomic_dec_and_test(v)          (atomic_sub_return(1, (v)) == 0)
#define atomic_inc_and_test(v)          (atomic_add_return(1, (v)) == 0)

#endif /* __linux__ && __KERNEL__ */

#endif /* _ATOMIC_H_ */
