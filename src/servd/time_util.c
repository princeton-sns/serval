#include "time_util.h"
#include "debug.h"

#include <stdint.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include <string.h>
#include <sys/errno.h>
#include <time.h>
#include <pthread.h>

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define LOW_RES_PER_TICK_MARK 10
#define HIGH_RES_PER_TICK_MARK 200

static int resolve_time_if_ticked();
static void reschedule_timer();
static void initialize_signal(int sigmask);
static void signal_handler(int sig);

static volatile sig_atomic_t resolve = TRUE;
static volatile sig_atomic_t resolution_since_last_tick = 0;
static pthread_mutex_t clock_mutex = PTHREAD_MUTEX_INITIALIZER;

//extern stack_t signal_stack;

struct ticked_clock {
    uint32_t ms_res;
    uint32_t avg_res_per_tick;
    int recurring;
    struct timespec prev;
    struct timespec now;
};

static struct ticked_clock global_clock = { .ms_res = 0, .avg_res_per_tick = 0, .recurring = 0 };
static void resolve_time();
void init_time(uint32_t res_interval) {

    bzero(&global_clock.prev, sizeof(struct timespec));
    bzero(&global_clock.now, sizeof(struct timespec));

    global_clock.ms_res = res_interval;
    initialize_signal(SA_RESTART);
}

static uint32_t time_diff_in_ms(struct timespec* now, struct timespec* prev) {

    long int sdiff = (now->tv_sec - prev->tv_sec) * 1000;

    if(now->tv_nsec > prev->tv_nsec) {
        sdiff += (1000000000 - prev->tv_nsec + now->tv_nsec) / 1000000 - 1000;
    } else {
        sdiff += now->tv_nsec - prev->tv_nsec;
    }
    return sdiff;
}

static int resolve_time_if_ticked() {
    /*does this need locking?*/
    if(resolve) {

        pthread_mutex_lock(&clock_mutex);
        if(resolve) {
            resolve_time();
            //track the ewma average
            uint32_t tdiff = time_diff_in_ms(&global_clock.now, &global_clock.prev);
            if(tdiff > 0) {
                global_clock.avg_res_per_tick = (((resolution_since_last_tick << 4) * 32) / (tdiff
                        / global_clock.ms_res) + global_clock.avg_res_per_tick * 96 + 64) / 128;
            }
            //reset the current tick count

            reschedule_timer();

            //LOG_DBG("Time resolved: %llu ms Resolutions: %i Avg resolutions per tick (16x): %u\n",
            //        global_clock.now.tv_sec * 1000LL + global_clock.now.tv_nsec / 1000000, resolution_since_last_tick, global_clock.avg_res_per_tick);
            resolution_since_last_tick = 0;
            resolve = FALSE;
        }

        pthread_mutex_unlock(&clock_mutex);
    }
    resolution_since_last_tick++;
    return 0;
}

static void reschedule_timer() {
    //LOG_DBG("Rescheduling timer: recurrent: %i resolution: %i\n", global_clock.recurring, global_clock.ms_res);
    if(global_clock.recurring) {
        if(global_clock.avg_res_per_tick < LOW_RES_PER_TICK_MARK) {
            //LOG_DBG("Avg resolutions per tick: %u < %i - change to on demand scheduling.\n", global_clock.avg_res_per_tick, LOW_RES_PER_TICK_MARK);
            struct itimerval itimer;
            bzero(&itimer, sizeof(itimer));

            itimer.it_value.tv_sec = global_clock.ms_res / 1000;
            itimer.it_value.tv_usec = (global_clock.ms_res % 1000) * 1000;

            if(setitimer(ITIMER_REAL, &itimer, NULL)) {
                LOG_ERR("Could not create an itimer with ms value: %u error: %s\n",
                        global_clock.ms_res, strerror(errno));
            }

            global_clock.recurring = FALSE;
        }
    } else if(global_clock.avg_res_per_tick > HIGH_RES_PER_TICK_MARK) {
        //LOG_DBG("Avg resolutions per tick: %u > %i - change to recurrent scheduling.\n", global_clock.avg_res_per_tick, HIGH_RES_PER_TICK_MARK);

        struct itimerval itimer;
        bzero(&itimer, sizeof(itimer));

        itimer.it_interval.tv_sec = global_clock.ms_res / 1000;
        itimer.it_interval.tv_usec = (global_clock.ms_res % 1000) * 1000;

        itimer.it_value = itimer.it_interval;

        //LOG_DBG("recurrent interval: %i.%06i recurrent start: %i.%06i\n", itimer.it_interval.tv_sec, itimer.it_interval.tv_usec, itimer.it_value.tv_sec, itimer.it_value.tv_usec);

        if(setitimer(ITIMER_REAL, &itimer, NULL)) {
            LOG_ERR("Could not create an itimer with ms value: %u error: %s\n",
                    global_clock.ms_res, strerror(errno));
        }

        global_clock.recurring = TRUE;
    } else {
        struct itimerval itimer;
        bzero(&itimer, sizeof(itimer));

        itimer.it_value.tv_sec = global_clock.ms_res / 1000;
        itimer.it_value.tv_usec = (global_clock.ms_res % 1000) * 1000;

        if(setitimer(ITIMER_REAL, &itimer, NULL)) {
            LOG_ERR("Could not create an itimer with ms value: %u error: %s\n",
                    global_clock.ms_res, strerror(errno));
        }
    }

}

time_t get_current_time() {
    resolve_time_if_ticked();
    return global_clock.now.tv_sec;
}

long long get_current_time_ms() {
    resolve_time_if_ticked();
    return global_clock.now.tv_sec * 1000LL + global_clock.now.tv_nsec / 1000000;
}

long long get_current_time_us() {
    resolve_time_if_ticked();
    return global_clock.now.tv_sec * 1000000LL + global_clock.now.tv_nsec / 1000;
}

long long resolve_current_time_ms() {
    if(resolve) {
        pthread_mutex_lock(&clock_mutex);
        resolve_time();
        pthread_mutex_unlock(&clock_mutex);
    }
    return global_clock.now.tv_sec * 1000LL + global_clock.now.tv_nsec / 1000000;
}

long long resolve_current_time_us() {
    if(resolve) {
        pthread_mutex_lock(&clock_mutex);
        resolve_time();
        pthread_mutex_unlock(&clock_mutex);

    }
    return global_clock.now.tv_sec * 1000000LL + global_clock.now.tv_nsec / 1000;
}

static void resolve_time() {
    //compute the interval in ms

    global_clock.prev = global_clock.now;

    //#if defined(OS_LINUX)
    //
    //    clock_gettime(CLOCK_REALTIME, &global_clock.now);
    //#endif
    //
    //#if defined(OS_BSD)
    struct timeval ctime;
    ctime.tv_sec = 0;
    ctime.tv_usec = 0;
    gettimeofday(&ctime, NULL);
    global_clock.now.tv_sec = ctime.tv_sec;
    global_clock.now.tv_nsec = ctime.tv_usec * 1000;
    //#endif
    //set_resolve(false);

    //LOG_DBG("resolved time: %i s, %lli ns, resolve: %i\n", (int) global_clock.now.tv_sec,
    //        (long long) global_clock.now.tv_nsec, resolve);
}

static void signal_handler(int sig) {
    //LOG_DBG("Signal received, setting resolve to true.\n");
    resolve = TRUE;
}

static void initialize_signal(int flags) {

    struct sigaction sa;
    struct sigaction osa;

    bzero(&sa, sizeof(sa));
    bzero(&osa, sizeof(osa));

    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = flags | SA_ONSTACK;
    if(sigaction(SIGALRM, &sa, &osa)) {
        LOG_ERR("sigaction(SIGALRM) failed: %s\n", strerror(errno));
    } else {
        //LOG_DBG("initialized signal clock with alarm handler\n");k
    }
}
