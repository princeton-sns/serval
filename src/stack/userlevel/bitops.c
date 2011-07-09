/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/bitops.h>
#include <serval/lock.h>

#define ATOMIC_HASH_SIZE        4

spinlock_t __atomic_hash[ATOMIC_HASH_SIZE] = {
        [0 ... (ATOMIC_HASH_SIZE-1)] = SPIN_LOCK_UNLOCKED
};
