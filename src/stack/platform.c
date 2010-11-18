/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/platform.h>
#if defined(__KERNEL__)
#include <linux/time.h>
#else
#include <time.h>
#endif

const char *mac_ntop(const void *src, char *dst, socklen_t size)
{	
	const char *mac = (const char *)src;

	if (size < 18)
		return NULL;

	sprintf(dst, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	return mac;
}

int mac_pton(const char *src, void *dst)
{
        return -1;
}

const char *get_strtime(void)
{
    static char buf[512];
#if defined(__KERNEL__)
    struct timeval now;

    do_gettimeofday(&now);
    sprintf(buf, "%ld.%03ld", now.tv_sec, now.tv_usec / 1000);
#else
    time_t now = time(0);
    struct tm p;
    localtime_r(&now, &p);
    strftime(buf, 512, "%b %e %T", &p);
#endif
    return buf;
}

#if defined(__KERNEL__)
#include <linux/inet.h>

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size)
{
        return NULL;
}

#endif /* __KERNEL__ */
