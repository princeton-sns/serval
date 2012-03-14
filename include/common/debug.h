/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <stdio.h>
#include "platform.h"

#if defined(OS_ANDROID)
#include <android/log.h>
#if defined(ENABLE_DEBUG)
#define LOG_DBG(format, ...) __android_log_print(ANDROID_LOG_DEBUG, "Serval",  \
                                                 "%s: "format, __func__, ## __VA_ARGS__)
#else
#define LOG_DBG(format, ...)
#endif /* ENABLE_DEBUG */
#define LOG_ERR(format, ...) __android_log_print(ANDROID_LOG_ERROR, "Serval", "%s: ERROR "format, \
                                                 __func__, ## __VA_ARGS__)
#else
#if defined(ENABLE_DEBUG)
#define LOG_DBG(format, ...) printf("%s: "format, __func__, ## __VA_ARGS__)
#else
#define LOG_DBG(format, ...)
#endif
#define LOG_ERR(format, ...) fprintf(stderr, "%s: ERROR "format, \
				     __func__, ## __VA_ARGS__)
#endif /* OS_ANDROID */

#endif /* _DEBUG_H_ */
