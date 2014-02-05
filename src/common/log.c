#include <common/log.h>
#include <string.h>
#include <sys/time.h>

struct log_handle __default_log = { .fp = NULL, LOG_F_TIMESTAMP };
struct log_handle __default_error_log = { .fp = NULL, LOG_F_TIMESTAMP };

/* Called automatically on library load */
__attribute__((constructor))
void __default_log_init(void)
{
    __default_log.fp = stdout;
    __default_error_log.fp = stderr;
}

int log_is_open(struct log_handle *lh)
{
    return lh->fp != NULL;
}

void log_set_flag(struct log_handle *lh, enum log_flag flag)
{
    lh->flags |= flag;
}

void log_unset_flag(struct log_handle *lh, enum log_flag flag)
{
    lh->flags &= ~flag;
}

int log_open(struct log_handle *lh, const char *path, enum log_mode lmode)
{
    char *mode;
    FILE *fp;
    
    switch (lmode) {
    case LOG_APPEND:
	mode = "a";
	break;
    case LOG_TRUNCATE:
	mode = "w";
	break;
    }
    
    fp = fopen(path, mode);
    
    if (!fp)
	return -1;

    memset(lh, 0, sizeof(*lh));
    lh->fp = fp;

    return 0;
}

void log_close(struct log_handle *lh)
{
    fclose(lh->fp);
    lh->fp = NULL;
}

int log_printf(struct log_handle *lh, const char *format, ...)
{
    va_list ap;
    int ret;
    
    va_start(ap, format);
    ret = log_vprintf(lh, format, ap);
    va_end(ap);
    
    return ret;
}

int log_vprintf(struct log_handle *lh, const char *format, va_list ap)
{
    int ret = 0;

    if (lh->flags & LOG_F_TIMESTAMP) {
	struct timeval now;
	gettimeofday(&now, NULL);
	
	ret = fprintf(lh->fp, "%ld.%06ld ", 
		      (long)now.tv_sec,		     
		      (long)now.tv_usec);
    }
	
    ret += vfprintf(lh->fp, format, ap);

    if (lh->flags & LOG_F_SYNC)
	fflush(lh->fp);

    return ret;
}
