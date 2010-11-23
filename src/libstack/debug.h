/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _DEBUG_H
#define _DEBUG_H

#if defined(ENABLE_DEBUG)
#include <stdio.h>
#include <errno.h>
#define LOG_DBG(fmt, ...) fprintf(stdout, "%s: "fmt, __func__, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) fprintf(stderr, "%s: ERROR"fmt, __func__, ##__VA_ARGS__)
#else
#define LOG_DBG(fmt, ...)
#define LOG_ERR(fmt, ...)
#endif /* ENABLE_DEBUG */

#endif /* _DEBUG_H */
