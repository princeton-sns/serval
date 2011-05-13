/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <stdio.h>

#define LOG_DBG(format, ...) printf("%s: "format, __func__, ## __VA_ARGS__)
#define LOG_ERR(format, ...) fprintf(stderr, "%s: ERROR "format, \
				     __func__, ## __VA_ARGS__)

#endif /* _DEBUG_H_ */
