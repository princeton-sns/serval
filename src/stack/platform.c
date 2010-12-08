/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/platform.h>
#include <scaffold/debug.h>
#if defined(OS_LINUX_KERNEL)
#include <linux/time.h>
#endif
#if defined(OS_USER)
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#endif

const char *mac_ntop(const void *src, char *dst, size_t size)
{	
	const char *mac = (const char *)src;

	if (size < 18)
		return NULL;

	sprintf(dst, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0] & 0xff, 
                mac[1] & 0xff, 
                mac[2] & 0xff, 
                mac[3] & 0xff, 
                mac[4] & 0xff, 
                mac[5] & 0xff);

	return mac;
}

int mac_pton(const char *src, void *dst)
{
        return -1;
}

const char *get_strtime(void)
{
    static char buf[30];
    struct timeval now;
#if defined(OS_LINUX_KERNEL)
    do_gettimeofday(&now);
#endif
#if defined(OS_USER)
    gettimeofday(&now, NULL);
#endif

    snprintf(buf, 30, "%ld.%03ld", now.tv_sec, now.tv_usec / 1000);

    return buf;
}

#if defined(OS_LINUX_KERNEL)
#include <linux/inet.h>

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size)
{
        unsigned char *ip = (unsigned char *)src;

        if (size < 16 || af != AF_INET)
                return NULL;
        
        sprintf(dst, "%u.%u.%u.%u", 
                ip[0], ip[1], ip[2], ip[3]);
        
        return dst;
}
#endif

#if defined(OS_USER)

int memcpy_toiovec(struct iovec *iov, unsigned char *from, int len)
{
        if (!memcpy(iov->iov_base, from, len)) 
                return -EFAULT;

        iov->iov_len = len;

        return 0;
}

int memcpy_fromiovec(unsigned char *to, struct iovec *iov, int len)
{
        if (!memcpy(to, iov->iov_base, iov->iov_len))
                return -EFAULT;

        return 0;
}


#if !defined(HAVE_PPOLL)
#include <poll.h>
#include <signal.h>

int ppoll(struct pollfd fds[], nfds_t nfds, struct timespec *timeout, sigset_t *set)
{
        int to = 0;
        sigset_t oldset;
        int ret;

        if (!timeout) {
                to = -1;
        } else if (timeout->tv_sec == 0 && timeout->tv_nsec == 0)  {
                to = 0;
        } else {
                to = timeout->tv_sec * 1000 + (timeout->tv_nsec / 1000000);
        }

        if (set) {
                /* TODO: make these operations atomic. */
                sigprocmask(SIG_SETMASK, set, &oldset);
                ret = poll(fds, nfds, to);
                sigprocmask(SIG_SETMASK, &oldset, NULL);
        } else {
                ret = poll(fds, nfds, to);
        }
        return ret;
}

#endif /* OS_ANDROID */

#endif /* OS_USER */
