/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Macros for printing debug information, which can be disabled at
 * compile time.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 *
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <stdio.h>
#include "platform.h"

#if defined(OS_ANDROID)
#include <android/log.h>
#if defined(ENABLE_DEBUG)
#define LOG_DBG(format, ...) __android_log_print(ANDROID_LOG_DEBUG, "Serval", \
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
#define LOG_ERR(format, ...) fprintf(stderr, "%s: ERROR "format,    \
                                     __func__, ## __VA_ARGS__)
#endif /* OS_ANDROID */

#endif /* _DEBUG_H_ */
