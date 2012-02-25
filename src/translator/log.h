/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _LOG_H_
#define _LOG_H_

#include <stdio.h>
#include <sys/types.h>

struct log_handle {
	char *path;
	FILE *f;
};

#define LOG_INIT { NULL, NULL }
#define LOG_DEFINE(name) \
	struct log_handle name = LOG_INIT;

int log_open(struct log_handle *lh, const char *path);
void log_close(struct log_handle *lh);
ssize_t log_write(struct log_handle *lh, const char *fmt, ...);
ssize_t log_write_line(struct log_handle *lh, const char *fmt, ...);
int log_is_open(struct log_handle *lh);

#endif /* _LOG_H_ */
