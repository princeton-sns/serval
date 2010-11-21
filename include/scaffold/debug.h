/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef __DEBUG_H_
#define __DEBUG_H_

#include <scaffold/platform.h>

#if defined(OS_LINUX_KERNEL)
#include <linux/kernel.h>
#include <linux/sched.h>
#elif defined(OS_USER)
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <errno.h> 
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

/* Allows convenient wrapping of kernel-style error codes (negative
 * error codes) into userlevel ones. */
#define KERN_ERR(err) (-(err))
#define KERN_STRERROR(err) (strerror(KERN_ERR(err)))
#endif /* OS_LINUX_KERNEL */

typedef enum {
	LOG_LEVEL_INF = 0,
	LOG_LEVEL_DBG,
	LOG_LEVEL_WARN,
	LOG_LEVEL_ERR,
	LOG_LEVEL_CRIT,
} log_level_t;

void logme(log_level_t level, const char *func, const char *format, ...);

#if defined(ENABLE_DEBUG)

#define LOG_CRIT(fmt, ...) logme(LOG_LEVEL_CRIT, __func__, fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) logme(LOG_LEVEL_ERR, __func__, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) logme(LOG_LEVEL_WARN, __func__, fmt, ##__VA_ARGS__)
#define LOG_DBG(fmt, ...) logme(LOG_LEVEL_DBG, __func__, fmt, ##__VA_ARGS__)
#define LOG_INF(fmt, ...) logme(LOG_LEVEL_INF, __func__, fmt, ##__VA_ARGS__)

#ifndef BUG_ON
#define BUG_ON(x) assert(!x)
#endif 

#else

#define LOG_CRIT(fmt, ...) logme(LOG_LEVEL_CRIT, __func__, fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) logme(LOG_LEVEL_ERR, __func__, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) logme(LOG_LEVEL_WARN, __func__, fmt, ##__VA_ARGS__)
#define LOG_DBG(fmt, ...)
#define LOG_INF(fmt, ...) logme(LOG_LEVEL_INF, __func__, fmt, ##__VA_ARGS__)

#ifndef BUG_ON
#define BUG_ON(x) 
#endif 

#endif /* ENABLE_DEBUG */

#endif /* __DEBUG_H_ */
