/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <stdlib.h>
#include <stdio.h>
#include "cmwc.h"

#define CMWC_A 18782LL
#define CMWC_B 4294967295LL
#define CMWC_R 4294967294LL

unsigned long c = 362436;
unsigned long Q[4096];

unsigned long cmwc4096(void)
{
    unsigned long long t, a = 18782LL, b = 4294967295LL;
    static unsigned long i = 4095;

    unsigned long r = b - 1;
    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (t >> 32);
    t = (t & b) + c;
    if (t > r) {
	c++;
	t = t - b;
    }

    return (Q[i] = r - t);
}

unsigned long scmwc4096(unsigned long *seed, unsigned long q[], int i)
{
    unsigned long long t, a = 18782LL, b = 4294967295LL;
    //static unsigned long i=4095;
    //unsigned long i = seed & 4095;
    unsigned long sd = *seed;

    unsigned long r = b - 1;
    i = i & 4095;
    t = a * q[i] + sd;
    sd = (t >> 32);
    t = (t & b) + sd;
    if (t > r) {
	sd++;
	t = t - b;
    }
    *seed = sd;
    return (r - t);
}

unsigned long ucmwc4096(unsigned long seed, unsigned long q[], int i)
{
    unsigned long long t;
    //static unsigned long i=4095;
    //unsigned long i = seed & 4095;

    i = i & 4095;
    t = CMWC_A * q[i] + seed;
    t = (t & CMWC_B) + (t >> 32);
    if (t > CMWC_R) {
	t = t - CMWC_B;
    }

    return (CMWC_R - t);
}
