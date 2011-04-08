#include "common.h"
#include <openssl/sha.h>
#include <sys/types.h>
#include <stdio.h>

static char *ticks[] = { "/", "-", "|", "-", "\\", "|" };

void print_tick() 
{
    static unsigned int i = 0;
    
    if (i == 6)
        i = 0;

    printf("\r %s    ", ticks[i++]);
    fflush(stdout);
}

const char *get_tick()
{
    static unsigned int i = 0;

    if (i == 6)
        i = 0;
    
    return ticks[i++];
}

const char *get_tick_i(unsigned int i)
{    
    return ticks[i % 6];
}

const char *digest_to_str(const unsigned char digest[SHA_DIGEST_LENGTH])
{
    static char digest_str[SHA_DIGEST_LENGTH * 2 + 1];
    size_t len = 0;
    int i;

    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        len += sprintf(digest_str + len, "%02x", digest[i]);
    }

    return digest_str;
}

int timeval_sub(struct timeval *res, struct timeval *x, struct timeval *y)
{
    long nsec = 0;

    /* Perform the carry for the later subtraction by updating y. */
    if (x->tv_usec < y->tv_usec) {
        nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
        y->tv_usec -= 1000000 * nsec;
        y->tv_sec += nsec;
    }
    if (x->tv_usec - y->tv_usec > 1000000) {
        nsec = (x->tv_usec - y->tv_usec) / 1000000;
        y->tv_usec += 1000000 * nsec;
        y->tv_sec -= nsec;
    }

    /* Compute the time remaining to wait.
       tv_usec is certainly positive. */
    res->tv_sec = x->tv_sec - y->tv_sec;
    res->tv_usec = x->tv_usec - y->tv_usec;

    /* Return 1 if res is negative. */
    return x->tv_sec < y->tv_sec;
}
