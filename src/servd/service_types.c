/*
 * service_types.c
 *
 *  Created on: Feb 24, 2011
 *      Author: daveds
 */

#include "service_types.h"
#include "task.h"
#include "stdlib.h"

struct sockaddr_sv service_router_prefix = {
    .sv_family = AF_SERVAL,
    .sv_flags = 0,
    .sv_prefix_bits = 16,
    .sv_srvid.srv_un.un_id8 = {219,219,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
};

void message_barrier_default_cb(struct message_barrier* barrier, uint16_t type, const void* message,
        size_t len) {

    /*perhaps not the best way to indicate asynchrony */
    atomic_dec(&barrier->message_count);

    if(type == barrier->type) {
        barrier->successes++;
        barrier->success_handler(barrier, message, len);
    } else {
        /* TODO error! */
        barrier->failures++;
        barrier->failure_handler(barrier, message, len);
    }

    if(atomic_read(&barrier->message_count) == 0) {
        if(barrier->callback == NULL) {
            /* TODO - may be necessary to notify on any message decrement - for windowed rpc*/
            task_mutex_lock(&barrier->barrier_mutex);
            task_cond_notify_all(&barrier->barrier_cond);
            task_mutex_unlock(&barrier->barrier_mutex);
        }
        else {
            barrier->trigger(barrier);

            /* free up the cruft - these must be heap allocated*/
            //TODO?free(barrier->callback);
            free(barrier->linger_data);
            free(barrier);
        }
    }
}

void wait_for_message_barrier(struct message_barrier* barrier) {
    task_mutex_lock(&barrier->barrier_mutex);
    while(atomic_read(&barrier->message_count) != 0) {
        task_cond_wait(&barrier->barrier_cond, &barrier->barrier_mutex);
    }
    task_mutex_unlock(&barrier->barrier_mutex);
}

void message_barrier_handle_success_default(struct message_barrier* barrier, const void* message,
        size_t len) {
}

void message_barrier_handle_failure_default(struct message_barrier* barrier, const void* message,
        size_t len) {
    /* error message? TODO */
}

void destroy_int_key(void* data) {
    if(data == NULL) {
        return;
    }
    int* xid = (int*) data;

    free(xid);
}

