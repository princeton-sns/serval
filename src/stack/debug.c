/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/debug.h>

static const char *log_level_str[] = {
	"INF",
	"DBG",
        "WARN",
	"ERR",
        "CRIT"
};

#if defined(OS_USER)
#include <pthread.h>
#endif

void logme(log_level_t level, const char *func, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	
#if defined(OS_LINUX_KERNEL)
	pr_info("%s{%d}[%3s]%s: ", 
		get_strtime(), task_pid_nr(current), 
                log_level_str[level], func);
	vprintk(format, ap);
#endif
#if defined(OS_USER)
	{
		FILE *s = stdout;

		switch (level) {
		case LOG_LEVEL_DBG:
		case LOG_LEVEL_INF:
			s = stdout;
			break;
		case LOG_LEVEL_ERR:
		case LOG_LEVEL_WARN:
		case LOG_LEVEL_CRIT:
			s = stderr;
			break;
		}
		fprintf(s, "%s{%010ld}[%3s]%s: ", 
			get_strtime(), (long)pthread_self(), 
                        log_level_str[level], func);
		vfprintf(s, format, ap);
		fflush(s);
	}
#endif
	va_end(ap);
}
