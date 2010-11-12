#ifndef _ATOMIC_H_
#define _ATOMIC_H_

#if defined(__KERNEL__)
#include <linux/kernel.h>
#else

typedef struct {
	int value;
} atomic_t;

static inline int atomic_read(atomic_t *v)
{
	return __sync_add_and_fetch(&v->value, 0);
}

static inline int atomic_add_return(int i, atomic_t *v)
{
	return __sync_add_and_fetch(&v->value, i);
}

static inline int atomic_sub_return(int i, atomic_t *v)
{
	return __sync_sub_and_fetch(&v->value, i);
}

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

#endif

#endif /* _ATOMIC_H_ */
