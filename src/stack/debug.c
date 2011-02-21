/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/debug.h>
#if defined(OS_USER)
#include <pthread.h>
#endif

static const char *log_level_str[] = {
	"INF",
	"DBG",
        "WARN",
	"ERR",
        "CRIT"
};

#if defined(OS_LINUX_KERNEL)
extern int log_vprintk(const char *levelstr, const char *func, 
                       const char *fmt, va_list args);
#endif

void logme(log_level_t level, const char *func, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
        
#if defined(OS_LINUX_KERNEL)
        switch (level) {
        case LOG_LEVEL_WARN:
        case LOG_LEVEL_CRIT:
        case LOG_LEVEL_ERR:
                pr_alert("{%d}[%3s]%s: ", 
                         task_pid_nr(current), 
                         log_level_str[level], func);
                vprintk(format, ap);
        case LOG_LEVEL_DBG:
        case LOG_LEVEL_INF:
                log_vprintk(log_level_str[level], func, format, ap);
                break;
        }
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
