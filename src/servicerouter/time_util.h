/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * time_util.h
 *
 *  Created on: Jul 28, 2010
 *      Author: daveds
 */

#ifndef _TIME_UTIL_H_
#define _TIME_UTIL_H_

#include <sys/types.h>
#include <sys/time.h>
//#include "timeval.h"
#include <signal.h>
#include <string.h>
#include <sys/errno.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>

#define DEFAULT_RESOLUTION_INTERVAL 1

void init_time(uint32_t res_interval);

time_t get_current_time();
long long get_current_time_ms();
long long resolve_current_time_ms();
long long get_current_time_us();
long long resolve_current_time_us();
//void resolve_time();
//bool should_resolve();

#endif				/* _TIME_UTIL_H_ */
