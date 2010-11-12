/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _THREAD_H
#define _THREAD_H

#if defined(__KERNEL__)
#include <linux/kernel.h>

/* typedef task_struct* thread_t; */

#else
#include <pthread.h>

typedef pthread_t thread_t;

#endif /* __KERNEL__ */

#endif /* _THREAD_H */
