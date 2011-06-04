/*
 * task_test.c
 *
 *  Created on: Mar 9, 2011
 *      Author: daveds
 */

#include "time_util.h"
#include "task.h"
#include "service_util.h"
#include "debug.h"
#include <sys/un.h>
#include <assert.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

/* test task locking - conditionals (mutex and r/w lock use the thread locks for simplicity),
 * create/kill/join - thread "ID" should never change unless yield or block called
 * block/unblock
 * sleep/yield
 *
 * timer tasks - initialize the clock
 *
 * simplest test should use a single thread
 * run up to 3 threads
 *
 */

#define TASK_TEST_SOCK_PATH "/tmp/task_test_server.sock"
#define TASK_TEST_CLIENT_PATH "/tmp/task_test_client.sock"

#define THREAD_COUNT 3
#define TASK_COUNT 5

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

static task_handle_t cond_tasks[TASK_COUNT];
static task_cond test_cond;
static task_mutex test_mutex;
static task_rwlock test_rwlock;
static int cond_count = 0;
static int yield_count = 0;
/* static int join_count = 0; */

struct test_task {
    int id;
    task_handle_t task;
    int count;
};

struct test_task tasks[TASK_COUNT];

static int thread_sleep(int ms) {
    struct timespec nap;
    struct timespec rnap;

    bzero(&nap, sizeof(nap));
    bzero(&rnap, sizeof(rnap));

    nap.tv_sec = ms / 1000;
    nap.tv_nsec = (ms % 1000) * 1000000;

    int elapsed = 0;
    //printf("Sleeping for %i ms\n", ms);
    while(rnap.tv_sec >= 0 && rnap.tv_nsec >= 0 && nanosleep(&nap, &rnap)) {

        nap.tv_sec -= rnap.tv_sec;

        if(rnap.tv_nsec > nap.tv_nsec) {
            nap.tv_sec--;

            nap.tv_nsec += (1000000000 - rnap.tv_nsec);
        } else {
            nap.tv_nsec -= rnap.tv_nsec;
        }

        elapsed += ((nap.tv_sec * 1000) + (nap.tv_nsec / 1000000));
        nap = rnap;
        //LOG_ERR("Sleep interrupted! elapsed: %i New sleep: %i.%09li\n", elapsed, (int) nap.tv_sec, nap.tv_nsec);

    }

    elapsed += ((nap.tv_sec * 1000) + (nap.tv_nsec / 1000000));
    //printf("time elapsed during sleep: %i.%09i elapsed total: %i\n", nap.tv_sec, nap.tv_nsec,
    //        elapsed);

    return elapsed;
}

static void remove_runner(void* data) {
    while(TRUE) {
        task_sleep(50);
        //thread_sleep(50);
        task_yield();
    }
}

static void cond_runner(void* data) {
    //struct test_task* ttask = (struct test_task*) data;
    task_mutex_lock(&test_mutex);
    cond_count++;
    task_mutex_unlock(&test_mutex);

    thread_sleep(50);

    task_yield();
    task_rwlock_wrlock(&test_rwlock);
    yield_count++;
    task_rwlock_unlock(&test_rwlock);
    thread_sleep(50);

    /*wait on the conditional which should free up the thread to handle the other tasks*/
    printf("about to lock on test mutex before cond wait\n");
    task_mutex_lock(&test_mutex);
    task_cond_wait(&test_cond, &test_mutex);
    cond_count--;
    task_mutex_unlock(&test_mutex);

    long long int start = get_current_time_ms();

    task_sleep(100);
    //thread_sleep(100);

    long long int end = get_current_time_ms();

    assert(end - start > 98);

}
static void interrupt_handler(int sig) {
    /*just continue on*/
    printf("thread interrupted\n");
}

stack_t signal_stack;

static void initialize() {
    bzero(&signal_stack, sizeof(signal_stack));
    signal_stack.ss_size = SIGSTKSZ;

    if((signal_stack.ss_sp = malloc(SIGSTKSZ)) == NULL) {
        perror("Could not allocated signal stack");
        exit(1);
    }

    if(sigaltstack(&signal_stack, NULL)) {
        perror("Could not set the signal stack");
        exit(1);
    }

    struct sigaction sa;

    bzero(&sa, sizeof(struct sigaction));
    sa.sa_handler = interrupt_handler;
    //sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_ONSTACK;

    sigaction(SIGINT, &sa, NULL);

    /*1 ms resolution clock*/
    init_time(1);
    initialize_tasks(THREAD_COUNT);

    task_cond_init(&test_cond);
    task_mutex_init(&test_mutex);
    task_rwlock_init(&test_rwlock);

}

static void finalize() {
    task_mutex_destroy(&test_mutex);
    task_cond_destroy(&test_cond);
    task_rwlock_destroy(&test_rwlock);
    printf("finalizing tasks\n");
    finalize_tasks();
    printf("finalized tasks\n");
}

static void test_task_conditional() {
    int i = 0;
    struct test_task* ttask;
    assert(task_count() == 1);
    assert(task_free_count() == 0);

    for(i = 0; i < TASK_COUNT; i++) {
        ttask = (struct test_task*) malloc(sizeof(*ttask));
        bzero(ttask, sizeof(*ttask));
        cond_tasks[i] = task_add(ttask, cond_runner);
        assert(is_valid_task(cond_tasks[i]));

    }

    /*add a task to remove*/
    struct test_task* rtask = (struct test_task*) malloc(sizeof(*rtask));
    bzero(rtask, sizeof(*rtask));
    task_handle_t remtask = task_add(rtask, remove_runner);

    assert(task_count() == TASK_COUNT + 2);
    assert(task_free_count() == 0);

    thread_sleep(25);

    printf("task count: %i time in ms: %llu\n", task_count(), get_current_time_ms());

    assert(cond_count == THREAD_COUNT - 1);

    thread_sleep(100 + 50 * TASK_COUNT);

    printf("post wait sleep cond count: %i time: %llums\n", cond_count, get_current_time_ms());
    assert(cond_count == TASK_COUNT);
    assert(is_valid_task(remtask));
    task_remove(remtask);

    thread_sleep(100 + 75 * TASK_COUNT);
    printf("post task remove wait sleep: %i time in ms: %llu\n", task_count(),
            get_current_time_ms());

    assert(!is_valid_task(remtask));
    assert(task_free_count() == 1);

    task_rwlock_rdlock(&test_rwlock);
    assert(yield_count == TASK_COUNT);
    task_rwlock_unlock(&test_rwlock);

    for(i = 1; i < 3; i++) {
        printf("notifying cond wait task\n");
        task_mutex_lock(&test_mutex);
        task_cond_notify(&test_cond);
        task_mutex_unlock(&test_mutex);

        thread_sleep(200);

        assert(cond_count == TASK_COUNT - i);
        printf("task count: %i time in ms: %llu\n", task_count(), get_current_time_ms());
        assert(task_count() == TASK_COUNT - i + 1);
    }

    task_mutex_lock(&test_mutex);
    task_cond_notify_all(&test_cond);
    task_mutex_unlock(&test_mutex);
    printf("about to sleep the main thread\n");
    thread_sleep(100 * TASK_COUNT);
    printf("post last sleep task count: %i time in ms: %llu\n", task_count(), get_current_time_ms());
    assert(cond_count == 0);
    assert(task_count() == 1);
    assert(task_free_count() == TASK_COUNT + 1);
    printf("finished cond test\n");

}

struct sock_info {
    int socket;
    struct sockaddr_un addr;
    int msg_count;
};

static void server_task(void* data) {
    struct sock_info* server_sock = (struct sock_info*) data;

    char buffer[1024];
    int nbytes = 0;

    int count = 0;
    while((nbytes = recv(server_sock->socket, buffer, 1024, MSG_DONTWAIT))) {
        if(nbytes < 0) {
            if(errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("server task blocking after receiving %i msgs\n", count);
                count = 0;
                task_block(server_sock->socket, FD_READ);
                printf("server task resumed from blocking\n");
                continue;
            }
        }
        printf("message len: %i\n", nbytes);
        printf("message: %s\n", buffer);
        count++;
        server_sock->msg_count++;
    }
}

static void client_task(void* data) {
    struct sock_info* client_sock = (struct sock_info*) data;

    client_sock->socket = socket(PF_UNIX, SOCK_DGRAM, 0);

    if(client_sock->socket < 0) {
        printf("Error creating client socket: %s\n", strerror(errno));
    }
    assert(client_sock->socket >= 0);

    int retval = bind(client_sock->socket, (struct sockaddr*) &client_sock->addr,
            sizeof(client_sock->addr));

    if(retval) {
        printf("Error binding client socket: %s\n", strerror(errno));
    }

    assert(retval == 0);

    make_async(client_sock->socket);
    set_reuse_ok(client_sock->socket);
    struct sockaddr_un saddr;
    bzero(&saddr, sizeof(saddr));
    saddr.sun_family = AF_UNIX;
    strcpy(saddr.sun_path, TASK_TEST_SOCK_PATH);

    retval = connect(client_sock->socket, (struct sockaddr*) &saddr, sizeof(saddr));

    if(retval) {
        printf("Error connecting to server: %s\n", strerror(errno));
    }

    assert(retval == 0);
    char buffer[1024];
    int nbytes = 0;

    int len = sprintf(buffer, "client message %i\n", client_sock->msg_count);
    while((nbytes = send(client_sock->socket, buffer, len + 1, MSG_DONTWAIT))) {
        if(nbytes < 0) {
            if(errno == EAGAIN || errno == EWOULDBLOCK) {
                task_block(client_sock->socket, FD_WRITE);
            }
        }
        client_sock->msg_count++;
        if(client_sock->msg_count % 5 == 0) {
            task_sleep(100);
        }

        len = sprintf(buffer, "client message %i\n", client_sock->msg_count);
    }
}

/* task block/unblock*/
static void test_task_block() {
    /*create a set of pipes for communication*/
    struct sock_info server_sock;
    bzero(&server_sock, sizeof(server_sock));

    /* dgram socket */
    server_sock.addr.sun_family = AF_UNIX;
    strcpy(server_sock.addr.sun_path, TASK_TEST_SOCK_PATH);
    server_sock.socket = socket(PF_UNIX, SOCK_DGRAM, 0);

    if(server_sock.socket < 0) {
        printf("Error creating server socket: %s\n", strerror(errno));
    }
    assert(server_sock.socket >= 0);

    int retval = bind(server_sock.socket, (struct sockaddr*) &server_sock.addr,
            sizeof(server_sock.addr));

    if(retval) {
        printf("Error binding socket: %s\n", strerror(errno));
    }

    assert(retval == 0);
    make_async(server_sock.socket);
    set_reuse_ok(server_sock.socket);
    task_handle_t stask = add_task_block(server_sock.socket, FD_READ, &server_sock, server_task);
    //task_handle_t stask = task_add(&server_sock, server_task);

    struct sock_info client_sock;
    bzero(&client_sock, sizeof(client_sock));

    /* dgram socket */
    client_sock.addr.sun_family = AF_UNIX;
    client_sock.addr.sun_family = AF_UNIX;
    strcpy(client_sock.addr.sun_path, TASK_TEST_CLIENT_PATH);

    task_handle_t ctask = task_add(&client_sock, client_task);

    assert(task_count() == 3);

    thread_sleep(50);
    printf("client msg: %i server msg: %i\n", client_sock.msg_count, server_sock.msg_count);
    assert(client_sock.msg_count == 5);
    assert(server_sock.msg_count == 5);
    thread_sleep(110);
    printf("client msg: %i server msg: %i\n", client_sock.msg_count, server_sock.msg_count);
    assert(client_sock.msg_count == 10);
    assert(server_sock.msg_count == 10);
    assert(task_unblock(server_sock.socket, FD_READ) == stask);
    thread_sleep(110);
    printf("client msg: %i server msg: %i\n", client_sock.msg_count, server_sock.msg_count);
    assert(client_sock.msg_count == 15);
    assert(server_sock.msg_count == 15);
    task_remove(stask);
    task_remove(ctask);

    assert(task_unblock(server_sock.socket, FD_READ) == stask);
    thread_sleep(110);
    printf("client msg: %i server msg: %i\n", client_sock.msg_count, server_sock.msg_count);

    assert(task_count() == 1);
    assert(client_sock.msg_count == 15);
    assert(server_sock.msg_count == 15);

    close(server_sock.socket);
    unlink(TASK_TEST_SOCK_PATH);
    close(client_sock.socket);
    unlink(TASK_TEST_CLIENT_PATH);
}

struct timer_info {
    int counter;
    int limit;
    struct timeval interval;
};

static void timer_task(void* data) {

    struct timer_info* tinfo = (struct timer_info*) data;

    tinfo->counter++;

    if(tinfo->counter < tinfo->limit) {

        add_timer_task(data, timer_task, &tinfo->interval);
    }
}

/* task timers*/
static void test_task_timer() {
    struct timer_info timer1;
    bzero(&timer1, sizeof(timer1));

    timer1.limit = 10;
    timer1.interval.tv_sec = 0;
    timer1.interval.tv_usec = 100000;
    task_handle_t ttask1 = add_timer_task(&timer1, timer_task, &timer1.interval);

    struct timer_info timer2;
    bzero(&timer2, sizeof(timer2));

    timer2.limit = 1;
    timer2.interval.tv_sec = 1;
    timer2.interval.tv_usec = 10000;

    task_handle_t ttask2 = add_timer_task(&timer2, timer_task, &timer2.interval);

    struct timer_info timer3;
    bzero(&timer3, sizeof(timer3));

    timer3.limit = 10;
    timer3.interval.tv_sec = 0;
    timer3.interval.tv_usec = 300000;

    task_handle_t ttask3 = add_timer_task(&timer3, timer_task, &timer3.interval);
    printf("timer1: %i timer2: %i timer3: %i taskcount: %i\n", timer1.counter, timer2.counter,
            timer3.counter, task_count());

    assert(task_count() == 4);

    assert(is_valid_timer_task(ttask1));
    assert(is_valid_timer_task(ttask2));
    assert(is_valid_timer_task(ttask3));
    thread_sleep(550);

    //    assert(is_valid_timer_task(ttask1));
    //    assert(is_valid_timer_task(ttask2));
    //    assert(is_valid_timer_task(ttask3));
    printf("timer1: %i timer2: %i timer3: %i taskcount: %i\n", timer1.counter, timer2.counter,
            timer3.counter, task_count());
    assert(timer1.counter == 5);
    assert(timer2.counter == 0);
    assert(timer3.counter == 1);
    thread_sleep(500);

    //    assert(!is_valid_timer_task(ttask1));
    //    assert(is_valid_timer_task(ttask2));
    //    assert(is_valid_timer_task(ttask3));
    printf("timer1: %i timer2: %i timer3: %i taskcount: %i\n", timer1.counter, timer2.counter,
            timer3.counter, task_count());
    assert(timer1.counter == 10);
    assert(timer2.counter == 1);
    assert(timer3.counter == 3);

    remove_timer_task(ttask3);
    //    assert(!is_valid_timer_task(ttask3));

    thread_sleep(100);
    printf("timer1: %i timer2: %i timer3: %i taskcount: %i\n", timer1.counter, timer2.counter,
            timer3.counter, task_count());

    assert(task_count() == 1);

    //    assert(!is_valid_timer_task(ttask1));
    //    assert(!is_valid_timer_task(ttask2));
    //    assert(!is_valid_timer_task(ttask3));
    assert(timer1.counter == 10);
    assert(timer2.counter == 1);
    assert(timer3.counter == 3);

    thread_sleep(1100);

    assert(task_count() == 1);

    //    assert(!is_valid_timer_task(ttask1));
    //    assert(!is_valid_timer_task(ttask2));
    //    assert(!is_valid_timer_task(ttask3));
    assert(timer1.counter == 10);
    assert(timer2.counter == 1);
    assert(timer3.counter == 3);

}

int main(int argc, char **argv) {
    initialize();
    test_task_conditional();
    test_task_timer();
    test_task_block();
    finalize();

    return 0;
}
