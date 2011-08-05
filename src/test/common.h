#ifndef _COMMON_H
#define _COMMON_H

#include <openssl/sha.h>
#include <sys/time.h>
#include <time.h>

#if defined(__cplusplus)
extern "C" {
#endif

void print_tick();
const char *get_tick();
const char *get_tick_i(unsigned int i);
const char *digest_to_str(const unsigned char digest[SHA_DIGEST_LENGTH]);
int timeval_sub(struct timeval *res, struct timeval *x, struct timeval *y);

#if defined(__cplusplus)
};
#endif

#endif
