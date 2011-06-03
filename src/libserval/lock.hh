/*
 * lock.hh
 *
 *  Created on: May 25, 2011
 *      Author: daveds
 */

#ifndef LOCK_HH_
#define LOCK_HH_

#include <pthread.h>
#include "log.hh"

class SimpleLock
{
    pthread_mutex_t &_m;

public:
    SimpleLock(pthread_mutex_t &m)
      : _m(m)
    {
        info("Locking\n");
        pthread_mutex_lock(&_m);
    }
    ~SimpleLock()
    {
        info("Unlocking\n");
        pthread_mutex_unlock(&_m);
    }
};

#endif /* LOCK_HH_ */
