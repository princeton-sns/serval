/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/debug.h>

static const char *log_level_str[] = {
	"INF",
	"DBG",
	"ERR",
        "CRIT"
};

void logme(log_level_t level, const char *func, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	
#if defined(__KERNEL__)
	pr_info("[%s {%d} %3s]%s: ", 
		get_strtime(), task_pid_nr(current), log_level_str[level], func);
	vprintk(format, ap);
#else
	{
		FILE *s = stdout;

		switch (level) {
		case LOG_LEVEL_DBG:
		case LOG_LEVEL_INF:
			s = stdout;
			break;
		case LOG_LEVEL_ERR:
		case LOG_LEVEL_CRIT:
			s = stderr;
			break;
		}
		fprintf(s, "[%s {%d} %3s]%s: ", 
			get_strtime(), getpid(), log_level_str[level], func);
		vfprintf(s, format, ap);
		fflush(s);
	}
#endif
	va_end(ap);
}
