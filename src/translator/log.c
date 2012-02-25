/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include "log.h"

int log_open(struct log_handle *lh, const char *path)
{
	memset(lh, 0, sizeof(*lh));
	
	lh->f = fopen(path, "a+");

	if (!lh->f) {
		fprintf(stderr, "Could not open %s: %s", 
			path, strerror(errno));
		return -1;
	}

	lh->path = malloc(strlen(path) + 1);

	if (!lh->path) {
		fclose(lh->f);
		return -1;
	}

	strcpy(lh->path, path);
	
	return 0;
}

void log_close(struct log_handle *lh)
{
	if (lh) {
		free(lh->path);
		fclose(lh->f);
	}
}

int log_is_open(struct log_handle *lh)
{
	return (lh && lh->f && lh->path);
}

ssize_t log_write(struct log_handle *lh, const char *fmt, ...)
{
	va_list ap;
	int len;

	if (!log_is_open(lh))
		return -1;

	va_start(ap, fmt);

	len = vfprintf(lh->f, fmt, ap);

	va_end(ap);

	if (len == -1) {
		fprintf(stderr, "could not write to log\n");
		return -1;
	}
	
	return len;
}

ssize_t log_write_line(struct log_handle *lh, const char *fmt, ...)
{
	va_list ap;
	time_t tm;
	int len, ret;
	char *ct;
	
	if (!log_is_open(lh))
		return -1;
	
	time(&tm);

	ct = ctime(&tm);
	
	/* Remove end of line */
	ct[strlen(ct) - 1] = '\0';

	ret = fprintf(lh->f, "[%s] ", ct);

	if (ret == -1) 
		return -1;
	
	len = ret;

	va_start(ap, fmt);

	ret = vfprintf(lh->f, fmt, ap);

	va_end(ap);

	if (ret == -1)
		return len;

	len += ret;
	
	if (fputc('\n', lh->f) != EOF)
		len++;
	
	return len;
}
