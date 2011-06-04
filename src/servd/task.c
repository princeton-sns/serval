/*
 * task.c
 *
 *  Created on: Feb 19, 2011
 *      Author: daveds
 */

#include "task.h"
#include "poll_reactor.h"
#include "serval/list.h"
#include "serval/atomic.h"

#include <pthread.h>
#include <signal.h>
#include <glib.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>

/* should use defines to enable 2 version - one thread and one coroutine based */

//#if defined(HAVE_PCL)
#include <pcl.h>

/*use a static thread pool for now - max/min would be good in the future - align with cores */
#define MAX_THREADS 4
#define MAX_HANDLE_RETRY 60
#define MAX_CACHED_TASKS 15

/* this is a tiny stack, but it really depends on the type of functions we're writing
 * places a limit on the depth of the call stack and especially recursion
 */
#define DEFAULT_STACK_SIZE 9192

static int max_threads = MAX_THREADS;

static task_handle_t next_handle = 1;

enum task_set {
    TASK_CREATED = 0,
    TASK_INITIALIZED = 1,
    TASK_RUNNING = 2,
    TASK_QUEUED = 3,
    TASK_RESCHEDULE = 4,
    TASK_SLEEP_WAIT = 5,
    TASK_TIMER_WAIT = 6,
    TASK_LOCK_WAIT = 7,
    TASK_COND_WAIT = 8,
    TASK_RWLOCK_WAIT = 9,
    TASK_BLOCK_WAIT = 10,
    TASK_TIME_WAIT = 11,
    TASK_JOIN_WAIT = 12,
    TASK_FINISHED = 13
};

struct co_task {
    struct list_head head;
    task_handle_t handle;
    atomic_t state;
    atomic_t finalize;

    coroutine_t task;
    coroutine_t resume_task;

    void* task_data;
    task_func task_func;

    stack_t stack;
    pthread_t runner;

    struct co_task* next;
};

struct task_set_ds {
    struct list_head free_tasks;
    int free_count;
    pthread_mutex_t task_mutex;
    GHashTable* task_table;
};

static struct task_set_ds task_set = {
        .free_tasks = LIST_HEAD_INIT(task_set.free_tasks),
        .free_count = 0,
        .task_mutex = PTHREAD_MUTEX_INITIALIZER,
        .task_table = NULL };

struct task_queue_ds {
    struct list_head work_queue;
    pthread_mutex_t work_mutex;
    pthread_cond_t work_cond;
    int task_count;
    int thread_count;
    int active;
};

static struct task_queue_ds task_queue = {
        .work_queue = LIST_HEAD_INIT(task_queue.work_queue),
        .work_mutex = PTHREAD_MUTEX_INITIALIZER,
        .work_cond = PTHREAD_COND_INITIALIZER,
        .task_count = 0,
        .thread_count = 0,
        .active = 0 };

static pthread_t* thread_pool;

static poll_reactor reactor = POLL_REACTOR_INIT;

static struct co_task* create_task(void* data, task_func tfunc);
static void release_task(struct co_task* task, int delete);
static void add_task_to_work_queue(struct co_task* task);
static void add_tasks_to_work_queue(struct list_head* head);

static void reactor_execute(void* target) {
    assert(target);
    struct co_task* task = (struct co_task*) target;

    add_task_to_work_queue(task);
}
static inline void* create_coroutine_stack(int size) {
    /*should really use a slab-allocator type routine*/
    void* stack = malloc(size);
    //assert(stack);

    return stack;
}


static inline char* print_task(struct co_task* task, char* buffer, int len) {
    snprintf(buffer, len, "task: handle(%li):runner(%li):"
	     "state(%i):stacksize(%zu)\n", task->handle,
	     task->runner, atomic_read(&task->state), task->stack.ss_size);

    return buffer;
}

static inline void _task_block(int fd, int flags, struct co_task* task) {

    if(flags & FD_ALL) {
        pr_set_interest(&reactor, fd, reactor_execute, task, 
			reactor_execute, task,
                reactor_execute, task);

    } else {
        if(flags & FD_READ) {
            pr_set_read(&reactor, fd, reactor_execute, task);
        }
        if(flags & FD_WRITE) {
            pr_set_write(&reactor, fd, reactor_execute, task);
        }
        if(flags & FD_ERROR) {
            pr_set_error(&reactor, fd, reactor_execute, task);
        }
    }
}

static void destroy_task(struct co_task* task, int del_coro) {
    assert(task);
    //char buffer[128];
    //LOG_DBG("destroying task: %s\n", print_task(task, buffer, 128));
    if(del_coro) {
        co_delete(task->task);
    }
    /*may or may not want to free the task data...TODO - perhaps this should be a flag to create_task (task add block, add task, add timer task)*/
    if(task->task_data) {
        //free(task->task_data);
        task->task_data = NULL;
    }
    if(task->stack.ss_sp) {
        free(task->stack.ss_sp);
        task->stack.ss_sp = NULL;
    }

    if(task->next) {
        if(del_coro) {
            co_delete(task->next->task);
        }
        if(task->next->task_data) {
            //free(task->next->task_data);
            task->next->task_data = NULL;
        }
        if(task->next->stack.ss_sp) {
            free(task->next->stack.ss_sp);
            task->next->stack.ss_sp = NULL;
        }

        free(task->next);
        task->next = NULL;
    }
    if(task->head.next && task->head.prev) {
        list_del(&task->head);
    }
    free(task);

}

/* main worker thread task execution/scheduling loop */
static void run_task_loop() {
    struct co_task* task;
    char buffer[128];

    /* increment the active worker thread count*/
    pthread_mutex_lock(&task_queue.work_mutex);
    task_queue.thread_count++;
    pthread_mutex_unlock(&task_queue.work_mutex);

    while (task_queue.active) {
        pthread_mutex_lock(&task_queue.work_mutex);

        /* this is probably necessary to prevent race conditions with the
         * task->runner check in add_task_to_work_queue */
        if(task != NULL && atomic_read(&task->state) == TASK_RESCHEDULE) {
            list_add_tail(&task->head, &task_queue.work_queue);
            task_queue.task_count++;
        }

        while (task_queue.task_count == 0) {
            //LOG_DBG("WORKER THREAD %i no queued tasks, waiting\n", (int) pthread_self());
            pthread_cond_wait(&task_queue.work_cond, &task_queue.work_mutex);
            if(!task_queue.active) {
                pthread_mutex_unlock(&task_queue.work_mutex);
                goto out;
            }
        }

        /*pull a task off and run it*/
        //LOG_DBG("WORKER THREAD %i task count: %i\n", (int) pthread_self(), task_queue.task_count);
task        = list_entry(task_queue.work_queue.next, struct co_task, head);
        assert(task);
        list_del(&task->head);
        task_queue.task_count--;

        //assert(atomic_read(&task->state) == TASK_QUEUED);
        //assert(task->runner == (pthread_t) -1);

        pthread_mutex_unlock(&task_queue.work_mutex);

        /* tasks can only be properly finalized (released and deleted)
         * when they are not actively executing, hence the release is
         * delayed until this point
         */
        if(atomic_read(&task->finalize) == TRUE) {
            //LOG_DBG("WORKER THREAD releasing finalized task\n");
            pthread_mutex_lock(&task_set.task_mutex);
            atomic_set(&task->state, TASK_FINISHED);
            release_task(task, FALSE);
            pthread_mutex_unlock(&task_set.task_mutex);
            task = NULL;
            continue;
        }

        /* only one thread should EVER be executing a task at any
         * given time
         */
        atomic_set(&task->state, TASK_RUNNING);
        task->runner = pthread_self();
        /* explicitly track the thread scheduler resume coroutine
         * context
         */
        task->resume_task = co_current();

        LOG_DBG("WORKER THREAD running task: %s\n", print_task(task, buffer, 128));
        co_call(task->task);
        //LOG_DBG("WORKER THREAD resumed from task: %s\n", buffer);
        task->runner = (pthread_t) 0;

        /* again, only release the task after execution has finished*/
        if(atomic_read(&task->state) == TASK_FINISHED) {
            pthread_mutex_lock(&task_set.task_mutex);
            //LOG_DBG("WORKER THREAD releasing finished task\n");
            release_task(task, FALSE);
            pthread_mutex_unlock(&task_set.task_mutex);
            task = NULL;
        }
    }

    out: LOG_DBG("WORKER THREAD terminating\n");
    pthread_mutex_lock(&task_queue.work_mutex);
    task_queue.thread_count--;
    pthread_mutex_unlock(&task_queue.work_mutex);

}

static void* start_task_worker(void* data) {
    /*initialize the thread coro*/
    //printf("starting task thread worker: %i\n", (int) pthread_self());
    int retval = co_thread_init();

    if(retval) {
        fprintf(stderr, "Could not init coroutine for thread: %s", strerror(errno));
        goto out;
    }

    /*mask appropriate signals*/
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGPIPE);
    sigaddset(&mask, SIGTERM);
    /*needed?*/sigaddset(&mask, SIGALRM);

    retval = pthread_sigmask(SIG_BLOCK, &mask, NULL);

    if(retval) {
        fprintf(stderr, "Could not set thread signal mask: %s", strerror(retval));
        goto out;
    }

    run_task_loop();

    /*done*/
    out: co_thread_cleanup();
    pthread_exit(0);
    return NULL;
}

static void poll_task(void* data) {
    pr_start((struct poll_reactor_ds*) data);
}

void initialize_tasks(int threads) {
    co_thread_init();
    task_set.task_table = g_hash_table_new(g_int_hash, g_int_equal);

    /*initialize the poll reactor*/
    reactor.threaded = TRUE;
    int retval = pr_initialize(&reactor);

    /*set the queue to active*/
    task_queue.active = TRUE;

    /*add the poll task*/
    task_handle_t ptask = task_add(&reactor, poll_task);

    reactor.poll_task = ptask;

    if(threads > 0) {
        max_threads = threads;
    }
    /*spin up the threads - daemonize?*/
    //pthread_attr_t attr;
    //pthread_attr_init(attr)
    int i = 0;
    thread_pool = (pthread_t*) malloc(sizeof(*thread_pool) * max_threads);
    for (; i < max_threads; i++) {
        retval = pthread_create(&thread_pool[i], NULL, start_task_worker, NULL);
    }
}

void finalize_tasks() {

    pr_stop(&reactor);

    pthread_mutex_lock(&task_queue.work_mutex);

    task_queue.active = FALSE;
    pthread_cond_broadcast(&task_queue.work_cond);
    pthread_mutex_unlock(&task_queue.work_mutex);

    int i = 0;
    int retval = 0;
    for (; i < max_threads; i++) {
        pthread_kill(thread_pool[i], SIGINT);
        /* pthread_cancel?? */

        LOG_DBG("Finalize: joining thread: %i\n", (int) thread_pool[i]);
        retval = pthread_join(thread_pool[i], NULL);
        if(retval) {
            LOG_ERR("Could not join killed thread: %s\n", strerror(retval));
        }
    }

    pthread_mutex_lock(&task_set.task_mutex);
    pthread_mutex_lock(&task_queue.work_mutex);

    pr_finalize(&reactor);

    /*need to clean up the conditional queue as well*/
    GHashTableIter iter;
    g_hash_table_iter_init(&iter, task_set.task_table);

    struct co_task* pos;
    struct co_task* temp;
    while (g_hash_table_iter_next(&iter, NULL, (void**) &pos)) {
        if(atomic_read(&pos->state) != TASK_RUNNING) {
            destroy_task(pos, TRUE);
        }
    }

    g_hash_table_destroy(task_set.task_table);

    list_for_each_entry_safe(pos, temp, &task_set.free_tasks, head) {
        destroy_task(pos, FALSE);
    }

    //    list_for_each_entry_safe(pos, temp, &task_queue.work_queue, head) {
    //        destroy_task(pos, TRUE);
    //    }

    pthread_mutex_unlock(&task_queue.work_mutex);
    pthread_mutex_unlock(&task_set.task_mutex);

    pthread_mutex_destroy(&task_queue.work_mutex);
    pthread_mutex_destroy(&task_set.task_mutex);
    pthread_cond_destroy(&task_queue.work_cond);
}

static void add_tasks_to_work_queue(struct list_head* head) {
    if(head == NULL || !task_queue.active) {
        return;
    }

    pthread_mutex_lock(&task_queue.work_mutex);

    struct co_task* task;
    int count = 0;

    //pthread_t sthread = pthread_self();
    list_for_each_entry(task, head, head) {
        //        if(pthread_equal(sthread, task->runner)) {
        //            atomic_set(&task->state, TASK_RESCHEDULE);
        //            list_del(&task->head);
        //            continue;
        //        }
        if(task->runner != 0) {
            atomic_set(&task->state, TASK_RESCHEDULE);
            list_del(&task->head);
            continue;
        }

        atomic_set(&task->state, TASK_QUEUED);
        //task->runner = (pthread_t) -1;
        count++;
    }

    //printf("added %i tasks to work queue\n", count);
    list_splice_tail(head, &task_queue.work_queue);

    int should_notify = !(task_queue.task_count) && task_queue.thread_count > 0 && count > 0;
    task_queue.task_count += count;

    /*notify waiting worker threads of new tasks*/
    if(should_notify) {
        //LOG_DBG("WORKER THREAD %i notifying workers of queued/pending tasks\n", (int) pthread_self());
        pthread_cond_broadcast(&task_queue.work_cond);
    }

    pthread_mutex_unlock(&task_queue.work_mutex);

}

static void add_task_to_work_queue(struct co_task* task) {
    if(task == NULL || !task_queue.active) {
        return;
    }

    /* relies on the fact that a thread trying to
     * queue its task will return the schedule loop
     * on resume and add the task to the work queue
     * to avoid simultaneous task execution race
     * conditions
     */
    //    if(pthread_equal(task->runner, pthread_self())) {
    //        atomic_set(&task->state, TASK_RESCHEDULE);
    //        return;
    //    }

    pthread_mutex_lock(&task_queue.work_mutex);

    if(task->runner != 0) {
        atomic_set(&task->state, TASK_RESCHEDULE);
        goto out;
    }

    //char buffer[128];
    //LOG_DBG("WORKER THREAD %i adding task to work queue(%i): %s\n", (int) pthread_self(),
    //        task_queue.task_count, print_task(task, buffer, 128));
    atomic_set(&task->state, TASK_QUEUED);

    //task->runner = (pthread_t) -1;

    /*TODO priority queuing is another option*/
    list_add_tail(&task->head, &task_queue.work_queue);

    int should_notify = !(task_queue.task_count) && task_queue.thread_count > 0;
    task_queue.task_count++;

    if(should_notify) {
        //LOG_DBG("WORKER THREAD %i notifying workers of queued/pending tasks\n", (int) pthread_self());
        pthread_cond_broadcast(&task_queue.work_cond);
    }

    out: pthread_mutex_unlock(&task_queue.work_mutex);
}

/* task mutex/locks still rely on pthread/system locks since multi-threaded atomicity is needed */

int task_cond_init(struct task_cond_t* cond) {
    assert(cond);
    INIT_LIST_HEAD(&cond->wait_queue);
    cond->wait_count = 0;

    return 0;
}

int task_cond_destroy(struct task_cond_t* cond) {
    assert(cond);
    if(cond->wait_count > 0) {
        return EBUSY;
    }
    return 0;
}

int task_cond_wait(struct task_cond_t* cond, task_mutex* mutex) {
    assert(cond && mutex);

    /*must have locked the mutex already! - should this also lock task_queue just in case? TODO*/
    struct co_task* task = (struct co_task*) co_get_data(co_current());

    //char buffer[128];
    //printf("about to wait on cond for task: %s\n", print_task(task, buffer, 128));

    if(atomic_read(&task->finalize) == TRUE) {
        /*let the thread handle it*/
        add_task_to_work_queue(task);
        /*EFINISHED?*/
        return 0;
    }

    list_add_tail(&task->head, &cond->wait_queue);
    atomic_set(&task->state, TASK_COND_WAIT);
    //task->runner = (pthread_t) -1;
    cond->wait_count++;

    int retval = task_mutex_unlock(mutex);

    if(retval) {
        LOG_ERR("Mutex unlock error: %s\n", strerror(retval));
        goto out;
    }

    /* yield to the scheduler*/assert(task->resume_task);
    co_call(task->resume_task);
    //printf("resuming from cond wait for task: %s\n", print_task(task, buffer, 128));
    retval = task_mutex_lock(mutex);
    out: return retval;
}

int task_cond_notify(struct task_cond_t* cond) {
    assert(cond);
    /*must be mutex locked!*/
    //printf("notifying task condition, %i waiting\n", cond->wait_count);
    if(cond->wait_count == 0) {
        return 0;
    }

    struct co_task* task;
    struct co_task* temp;

    list_for_each_entry_safe(task, temp, &cond->wait_queue, head)
    {

        list_del(&task->head);
        /*add task to work queue*/
        add_task_to_work_queue(task);
        /*find a non finalizing task to notify and run*/
        if(atomic_read(&task->finalize) == TRUE) {
            continue;
        }
        break;
    }

    return 0;
}

int task_cond_notify_all(struct task_cond_t* cond) {
    assert(cond);
    /*must be mutex locked!*/
    //printf("notifying all task conditions, %i waiting\n", cond->wait_count);
    if(cond->wait_count == 0) {
        return 0;
    }

    add_tasks_to_work_queue(&cond->wait_queue);
    return 0;
}

int task_join(task_handle_t handle) {
    pthread_mutex_lock(&task_set.task_mutex);
    /*remove from the task table*/
    struct co_task* task = g_hash_table_lookup(task_set.task_table, &handle);
    int retval = 0;

    if(task == NULL) {
        /* the task may have been released already*/
        retval = EINVAL;
        goto error;
    }

    struct co_task* ctask = (struct co_task*) co_get_data(co_current());
    //char buffer[128];

    //printf("joining task: %s current thread %i\n", print_task(task, buffer, 128),
    //        (int) pthread_self());
    atomic_set(&ctask->state, TASK_JOIN_WAIT);
    //ctask->runner = (pthread_t) -1;
    /* we just need to ensure that the task is not released prior to the join*/
    task->next = ctask;
    pthread_mutex_unlock(&task_set.task_mutex);

    assert(task->resume_task);
    co_call(task->resume_task);

    //printf("task joined: state %i\n", ctask->state);
    return retval;

    error: pthread_mutex_unlock(&task_set.task_mutex);
    return retval;
}

static void release_task(struct co_task* task, int delete) {
    if(task == NULL) {
        return;
    }
    /*release the task*/
    struct co_task* next = task->next;

    char buffer[128];

    LOG_DBG("releasing task: %s delete %i\n", print_task(task, buffer, 128), delete);

    /*remove from the task table*/

    g_hash_table_remove(task_set.task_table, &task->handle);

    if(delete) {
        co_delete(task->task);
    }

    if(task_queue.active && task_queue.task_count < MAX_CACHED_TASKS) {
        atomic_set(&task->state, TASK_CREATED);
        atomic_set(&task->finalize, FALSE);
        task->next = NULL;

        /* TODO - this could be a memory leak if task_data was allocated on the heap
         * and not cleaned up in the task func
         */
        task->task_data = NULL;
        task->task_func = NULL;
        /* TODO "null" out the task and resume_task?*/
        task->runner = (pthread_t) 0;
        /*zero out the stack?*/
        list_add_tail(&task->head, &task_set.free_tasks);
        task_set.free_count++;
    } else {
        free(task->stack.ss_sp);
        free(task);
    }
    /*task_set before task_queue lock*/
    if(next) {
        add_task_to_work_queue(next);
    }

}

/* TODO this function wrapper is only needed
 * for setting the task state to signal exec completion
 * it would be nice to elide it since the coroutine already
 * calls a function with data
 */
static void execute_task(void* data) {
    struct co_task* task = (struct co_task*) data;
    //char buffer[128];
    //printf("executing task: %s\n", print_task(task, buffer, 128));

    task->task_func(task->task_data);

    /*protection needed?*/atomic_set(&task->state, TASK_FINISHED);
    /* when the task is done executing, yield to the scheduler - effectively a resume*/
    //co_exit();
    assert(task->resume_task);
    co_exit_to(task->resume_task);
}

static task_handle_t get_next_handle() {
    task_handle_t handle = next_handle++;

    /*look for existing/collision -> try 50 then go random another 10 times*/
    int retries = 0;

    while (retries < MAX_HANDLE_RETRY && g_hash_table_lookup_extended(task_set.task_table, &handle,
            NULL, NULL)) {
        if(retries < 50) {
            next_handle++;
        } else {
            next_handle = random();
        }
        retries++;
    }

    return handle;

}

static struct co_task* create_task(void* data, task_func tfunc) {
    struct co_task* task = NULL;

    pthread_mutex_lock(&task_set.task_mutex);
    /* create a new task*/
    if(!list_empty(&task_set.free_tasks)) {
        assert(task_set.free_count > 0);
        task = list_entry(task_set.free_tasks.next, struct co_task, head);
        list_del(&task->head);
        task_set.free_count--;
        atomic_set(&task->state, TASK_INITIALIZED);

        if(g_hash_table_lookup(task_set.task_table, &task->handle) != NULL) {
            task->handle = get_next_handle();
        }
    }

    if(task == NULL) {
        task = (struct co_task*) malloc(sizeof(*task));
        bzero(task, sizeof(*task));

        atomic_set(&task->state, TASK_INITIALIZED);
        task->stack.ss_sp = create_coroutine_stack(DEFAULT_STACK_SIZE);

        if(task->stack.ss_sp == NULL) {
            LOG_ERR("Could not create task stack!");
            free(task);
            task = NULL;
            goto out;
        }

        task->stack.ss_size = DEFAULT_STACK_SIZE;
        task->handle = get_next_handle();
    }

    task->task_data = data;
    task->task_func = tfunc;

    task->task = co_create(execute_task, task, task->stack.ss_sp, task->stack.ss_size);

    /*add to task table */
    g_hash_table_insert(task_set.task_table, &task->handle, task);

    //char buffer[128];
    //LOG_DBG("created task(%i): %s\n", g_hash_table_size(task_set.task_table), print_task(task,
    //                buffer, 128));

    out: pthread_mutex_unlock(&task_set.task_mutex);
    return task;
}

task_handle_t task_add(void* data, task_func tfunc) {
    assert(tfunc);

    struct co_task* task = create_task(data, tfunc);

    if(task) {
        /*add to work queue*/
        add_task_to_work_queue(task);

        return task->handle;
    }
    return -1;
}

int task_remove(task_handle_t handle) {
    pthread_mutex_lock(&task_set.task_mutex);
    /*remove from the task table*/
    struct co_task* task = g_hash_table_lookup(task_set.task_table, &handle);
    //struct co_task* qtask;
    //struct co_task* temp;
    if(task == NULL) {
        goto out;
    }

    char buffer[128];
    LOG_DBG("removing task: %s\n", print_task(task, buffer, 128));

    /*set the state to finished and allow the thread to finalize it
     * lock the queue to ensure that TASK_QUEUE doesn't override
     * */atomic_set(&task->finalize, TRUE);

    out: pthread_mutex_unlock(&task_set.task_mutex);
    return 0;
}

int is_valid_task(task_handle_t handle) {
    pthread_mutex_lock(&task_set.task_mutex);
    /*remove from the task table*/
    struct co_task* task = g_hash_table_lookup(task_set.task_table, &handle);
    pthread_mutex_unlock(&task_set.task_mutex);

    return task != NULL && !atomic_read(&task->finalize);
}

int task_count() {
    int count = 0;
    pthread_mutex_lock(&task_set.task_mutex);
    count = g_hash_table_size(task_set.task_table);
    pthread_mutex_unlock(&task_set.task_mutex);
    return count;
}

int task_free_count() {
    int count = 0;
    pthread_mutex_lock(&task_set.task_mutex);
    count = task_set.free_count;
    pthread_mutex_unlock(&task_set.task_mutex);
    return count;
}

void task_yield() {
    struct co_task* task = (struct co_task*) co_get_data(co_current());

    //char buffer[128];
    //LOG_DBG("yielding task: %s\n", print_task(task, buffer, 128));

    add_task_to_work_queue(task);

    /*always go back to the scheduler coroutine*/assert(task->resume_task);
    co_call(task->resume_task);
}

/* there could be quite a few timer tasks and not every one needs it's own thread/stack
 * it might be better to use a pool (free tasks) for executing timers (as a list)
 * */
task_handle_t add_timer_task(void* data, task_func tfunc, struct timeval* tval) {
    assert(tfunc);

    struct co_task* task = create_task(data, tfunc);

    task_handle_t handle = task->handle;

    atomic_set(&task->state, TASK_TIMER_WAIT);
    pr_add_timeout(&reactor, tval->tv_sec * 1000 + tval->tv_usec / 1000, reactor_execute, task);

    return handle;
}

int remove_timer_task(task_handle_t handle) {

    pthread_mutex_lock(&task_set.task_mutex);

    struct co_task* task = g_hash_table_lookup(task_set.task_table, &handle);
    int retval = 0;
    if(task == NULL) {
        retval = EINVAL;
        goto out;
    }

    char buffer[128];
    LOG_DBG("Removing timer task: %s\n", print_task(task, buffer, 128));
    atomic_set(&task->finalize, TRUE);

    if(atomic_read(&task->state) == TASK_TIMER_WAIT) {
        /* timeout canceled */

        if(pr_cancel_timeout(&reactor, reactor_execute, task) == 0) {
            /* schedule the task to be released by a worker thread*/
            add_task_to_work_queue(task);
        }
    }
    /* else the task is either queued, running, or in some other state that
     * finalize should catch.
     */

    out: pthread_mutex_unlock(&task_set.task_mutex);
    return retval;
}

int is_valid_timer_task(task_handle_t handle) {

    pthread_mutex_lock(&task_set.task_mutex);

    struct co_task* task = g_hash_table_lookup(task_set.task_table, &handle);
    int retval = FALSE;
    if(task == NULL) {
        LOG_DBG("Task handle not found - invalid timer task\n");
        goto out;
    }

    retval = pr_is_waiting(&reactor, reactor_execute, task);

    out: pthread_mutex_unlock(&task_set.task_mutex);

    return retval;

}

void task_block(int fd, int flags) {
    /*add the current task to the poll set*/
    struct co_task* task = (struct co_task*) co_get_data(co_current());
    char buffer[128];
    LOG_DBG("blocking on fd: %i, flags: %i, task: %s\n", fd, flags, print_task(task, buffer, 128));

    if(atomic_read(&task->finalize) == TRUE) {
        /*let the thread handle it*/
        add_task_to_work_queue(task);
        /*EFINISHED?*/
        return;
    }

    _task_block(fd, flags, task);

    assert(task->resume_task);
    co_call(task->resume_task);

    //printf("done blocking on fd: %i, flags: %i, task: %s\n", fd, flags, print_task(task, buffer,
    //        128));
}

task_handle_t add_task_block(int fd, int flags, void* data, task_func tfunc) {
    assert(tfunc);

    struct co_task* task = create_task(data, tfunc);
    //char buffer[128];
    //LOG_DBG("adding task block on fd: %i, flags: %i, task: %s\n", flags, fd, print_task(task,
    //                buffer, 128));

    _task_block(fd, flags, task);
    return task->handle;
}

task_handle_t task_unblock(int fd, int flags) {

    struct co_task* task = NULL;

    if(flags & FD_ALL) {
        task = (struct co_task*) pr_clear_interest(&reactor, fd);
    } else {
        if(flags & FD_READ) {
            task = (struct co_task*) pr_clear_read(&reactor, fd);
        }
        if(flags & FD_WRITE) {
            task = (struct co_task*) pr_clear_write(&reactor, fd);
        }
        if(flags & FD_ERROR) {
            task = (struct co_task*) pr_clear_error(&reactor, fd);
        }
    }

    if(task != NULL) {
        char buffer[128];
        LOG_DBG("unblocking task on fd: %i, flags: %i, task: %s\n", fd, flags, print_task(task,
                        buffer, 128));

        add_task_to_work_queue(task);
        return task->handle;
    }

    return 0;

}

void task_sleep(int ms) {
    assert(ms >= 0);

    struct co_task* task = (struct co_task*) co_get_data(co_current());
    //char buffer[128];
    //LOG_DBG("task sleep for %ims task: %s\n", ms, print_task(task, buffer, 128));

    if(atomic_read(&task->finalize) == TRUE) {
        /*let the thread handle it*/
        add_task_to_work_queue(task);
        /*EFINISHED?*/
        return;
    }

    atomic_set(&task->state, TASK_SLEEP_WAIT);
    //task->runner = -1;
    pr_add_timeout(&reactor, ms, reactor_execute, task);

    assert(task->resume_task);
    co_call(task->resume_task);

    //printf("done sleeping for task: %s\n", print_task(task, buffer, 128));
}

int task_kill(task_handle_t handle, int signal) {

    pthread_mutex_lock(&task_set.task_mutex);

    struct co_task* task = g_hash_table_lookup(task_set.task_table, &handle);
    int retval = 0;
    if(task == NULL) {
        retval = ESRCH;
        goto out;
    }
    //char buffer[128];
    //LOG_DBG("killing task: %s\n", print_task(task, buffer, 128));

    /*this may be strange, but for now, only deliver signals to running tasks*/
    if(atomic_read(&task->state) == TASK_RUNNING) {
        retval = pthread_kill(task->runner, signal);

    } else {
        /* TODO - this should also handle cond wait tasks as well - move to active queue with pending signal
         * for lock states, this would require setting the task state properly, i.e. TASK_LOCK_WAIT for
         * task_mutex_lock, etc
         * */
        retval = ESRCH;
    }

    out: pthread_mutex_unlock(&task_set.task_mutex);
    return retval;
}

//#endif

//struct task_mutex_t {
//    LIST_HEAD(lock_queue);
//    uint32_t lock_count;
//    co_task* own_task;
//    pthread_mutex_t mutex;
//};
//struct task_rwlock_t {
//    LIST_HEAD(read_queue);
//    LIST_HEAD(write_queue);
//    uint32_t read_pending;
//    uint32_t write_pending;
//    uint32_t readers;
//    uint32_t writer;
//    pthread_mutex_t mutex;
//};
//
//int task_mutex_init(task_mutex* mutex) {
//    assert(mutex);
//    INIT_LIST_HEAD(&mutex->lock_queue);
//    mutex->lock_count = 0;
//    mutex->own_task = NULL;
//    pthread_mutex_init(&mutex->mutex);
//}
//
//int task_mutex_destroy(task_mutex* mutex) {
//    assert(mutex);
//    int retval = 0;
//    pthread_mutex_lock(&mutex->mutex);
//
//    if(mutex->own_task) {
//        retval = EBUSY;
//        goto out;
//    }
//
//    assert(mutex->lock_count == 0);
//
//    //    struct list_head* pos;
//    //    list_for_each_entry(pos, mutex->lock_queue, lock_queue) {
//    //        list_del(pos);
//    //        free(pos);
//    //    }
//
//    out: pthread_mutex_unlock(&mutex->mutex);
//
//    if(retval == 0) {
//        pthread_mutex_destroy(&mutex->mutex);
//    }
//    return retval;
//}
//
//static int _task_mutex_lock(task_mutex* mutex, int BLOCK) {
//    assert(mutex);
//    /*use atomic test/set?*/
//
//    struct co_task* task = (struct co_task*) co_get_data(co_current());
//
//    int retval = pthread_mutex_lock(&mutex->mutex);
//
//    if(retval) {
//        goto out;
//    }
//
//    if(mutex->own_task == NULL) {
//        mutex->own_task = task;
//    } else if(mutex->own_task != task) {
//        if(block) {
//            /* what to do if interrupted or task destroyed?*/
//
//            /*lock it*/
//            task->state = TASK_LOCK_WAIT;
//
//
//            list_add_tail(&task->head, &mutex->lock_queue);
//            mutex->lock_count++;
//            pthread_mutex_unlock(&mutex->mutex);
//            /*should only be "woken up" if it is the next owner*/
//            co_resume();
//
//            return retval;
//        } else {
//            retval = EBUSY;
//        }
//    }
//
//    out: pthread_mutex_unlock(&mutex->mutex);
//
//    return retval;
//}
//int task_mutex_lock(task_mutex* mutex) {
//    return _task_mutex_lock(mutex, TRUE);
//}
//
//int task_mutex_trylock(task_mutex* mutex) {
//    return _task_mutex_lock(mutex, FALSE);
//}
//
//int task_mutex_unlock(task_mutex* mutex) {
//    assert(mutex);
//    /*use atomic test/set?*/
//
//    struct co_task* task = (struct co_task*) co_get_data(co_current());
//    int retval = pthread_mutex_lock(&mutex->mutex);
//
//    if(retval) {
//        return retval;
//    }
//
//    if(mutex->own_task != task) {
//        /* was never the owner!*/
//        retval = EPERM;
//        goto out;
//    } else {
//        /*unlock it*/
//        if(mutex->lock_count == 0) {
//            mutex->own_task = NULL;
//        } else {
//            task =
//                    container_of(mutex->lock_queue->next, struct co_task, head);
//            list_del(&task->head);
//            task->state = TASK_RUNNING;
//
//            mutex->own_task = task;
//            mutex->lock_count--;
//
//            /*add the task back to the work queue TODO */
//            add_task_to_work_queue(entry);
//        }
//    }
//
//    out: retval = pthread_mutex_unlock(&mutex->mutex);
//    return retval;
//}
//
//int task_rwlock_init(task_rwlock* rwlock) {
//    assert(rwlock);
//    INIT_LIST_HEAD(&rwlock->read_queue);
//    INIT_LIST_HEAD(&rwlock->write_queue);
//
//    mutex->read_count = 0;
//    mutex->write_count = 0;
//    mutex->read_pending = 0;
//    mutex->write_pending = 0;
//    pthread_mutex_init(&rwlock->mutex);
//}
//
//int task_rwlock_destroy(task_rwlock* rwlock) {
//    assert(rwlock);
//
//    int retval = 0;
//    pthread_mutex_lock(&rwlock->mutex);
//
//    if(mutex->read_count > 0 || mutex->write_count > 0) {
//        retval = EBUSY;
//        goto out;
//    }
//
//    assert(mutex->read_pending == 0);
//    assert(mutex->write_pending == 0);
//    assert(list_empty(&rwlock->read_queue));
//    assert(list_empty(&rwlock->write_queue));
//
//    out: pthread_mutex_unlock(&rwlock->mutex);
//
//    if(retval == 0) {
//        pthread_mutex_destroy(&rwlock->mutex);
//    }
//    return retval;
//
//}
//
//static inline int find_task(struct list_head* head, struct co_task* task) {
//    int ind = 0;
//    struct list_head* next = head->next;
//    while(next != head) {
//        if(next == task) {
//            return ind;
//        }
//        ind++;
//        next = next->next;
//    }
//    return -1;
//}

//static int _task_rwlock_rdlock(task_rwlock* rwlock, int block) {
//    assert(rwlock);
//    /*use atomic test/set?*/
//
//    struct co_task* task = (struct co_task*) co_get_data(co_current());
//
//    int retval = pthread_mutex_lock(&rwlock->mutex);
//
//    if(retval) {
//        goto out;
//    }
//
//    /*check if the read lock is already obtained*/
//    return retval;
//
//    int pos = -1;
//    if(rwlock->write_count == 0) {
//        /*TODO - self adjust the read/write yield ratios*/
//        if(find_task(&rwlock->read_queue, task) >= 0) {
//            goto out;
//        } else {
//            list_add_tail(&task->head, &rwlock->read_queue);
//
//            if(rwlock->write_pending == 0) {
//
//                /*make it a reader*/
//                rwlock->readers++;
//            } else if(block) {
//                task->state = TASK_READ_LOCK_WAIT;
//                rwlock->read_pending++;
//                retval = pthread_mutex_unlock(&mutex->mutex);
//                co_resume();
//                return retval;
//            } else {
//                retval = EBUSY;
//                goto out;
//            }
//
//        }
//    } else if(find_task(&rwlock->write_queue, task) >= 0) {
//        goto out;
//    } else if(block) {
//        /*block on the writer*/
//        task->state = TASK_READ_LOCK_WAIT;
//        list_add_tail(&task->head, &rwlock->read_queue);
//
//        rwlock->read_pending++;
//        retval = pthread_mutex_unlock(&mutex->mutex);
//        co_resume();
//        return retval;
//
//    } else {
//        retval = EBUSY;
//    }
//
//    out: pthread_mutex_unlock(&mutex->mutex);
//
//    return retval;
//}
//
//int task_rwlock_rdlock(task_rwlock* rwlock) {
//    return _task_rwlock_rdlock(rwlock, TRUE);
//}
//
//int task_rwlock_tryrdlock(task_rwlock* rwlock) {
//    return _task_rwlock_rdlock(rwlock, FALSE);
//}
//
//static int _task_rwlock_wrlock(task_rwlock* rwlock, int block) {
//    assert(rwlock);
//    /*use atomic test/set?*/
//
//    struct co_task* task = (struct co_task*) co_get_data(co_current());
//
//    int retval = pthread_mutex_lock(&rwlock->mutex);
//
//    if(retval) {
//        goto out;
//    }
//
//    /*check if the read lock is already obtained*/
//    if(rwlock->write_count == 0) {
//        if(rwlock->read_count == 0) {
//            /*add/upgrade to write lock - nobody pending!!*/
//            /*make it the writer*/
//            list_add_tail(&task->head, &rwlock->write_queue);
//            rwlock->writer++;
//        } else if(rwlock->read_count == 1 && find_task(&rwlock->read_queue, task) >= 0) {
//            /* move from read to write queue*/
//            list_del(&task->head);
//            rwlock->readers--;
//
//            list_add_tail(&task->head, &rwlock->write_queue);
//            rwlock->writer++;
//        } else if(block) {
//            /* there are readers */
//            list_add_tail(&task->head, &rwlock->write_queue);
//            task->state = TASK_WRITE_LOCK_WAIT;
//            rwlock->write_pending++;
//
//            retval = pthread_mutex_unlock(&mutex->mutex);
//            co_resume();
//
//            return retval;
//        } else {
//            retval = EBUSY;
//            goto out;
//        }
//    } else if(find_task(&rwlock->write_queue, task)) {
//        goto out;
//    } else if(block) {
//        /* there is a writer*/
//        list_add_tail(&task->head, &rwlock->write_queue);
//        task->state = TASK_WRITE_LOCK_WAIT;
//        rwlock->write_pending++;
//        retval = pthread_mutex_unlock(&mutex->mutex);
//
//        co_resume();
//
//        return retval;
//    } else {
//        retval = EBUSY;
//    }
//
//    out: retval = pthread_mutex_unlock(&mutex->mutex);
//
//    return retval;
//
//}
//
//int task_rwlock_wrlock(task_rwlock* rwlock) {
//    return _task_rwlock_wrlock(rwlock, TRUE);
//
//}
//
//int task_rwlock_trywrlock(task_rwlock* rwlock) {
//    return _task_rwlock_wrlock(rwlock, FALSE);
//
//}
//
//int task_rwlock_unlock(task_rwlock* rwlock) {
//    assert(mutex);
//    /*use atomic test/set?*/
//    struct co_task* task = (struct co_task*) co_get_data(co_current());
//    int retval = pthread_mutex_lock(&mutex->mutex);
//
//    if(retval) {
//        return retval;
//    }
//    /*if the task is in the pending queue - its a major error!*/
//    if(rwlock->read_count == 0 && rwlock->write_count == 0) {
//        /* was never the owner!*/
//        retval = EPERM;
//        goto out;
//    } else {
//        int pos = find_task(&rwlock->write_queue, task);
//
//        if(pos < 0) {
//            /*look in the read queue - there must not be an active writer!*/
//            pos = find_task(&rwlock->read_queue, task);
//            if(pos < 0) {
//                retval = EPERM;
//                goto out;
//            } else if(pos < rwlock->read_count) {
//                list_del(&task->head);
//                rwlock->readers--;
//
//                if(rwlock->read_count == 0) {
//                    if(rwlock->write_pending > 0) {
//                        /*give the writers a chance*/
//                        task = container_of(rwlock->write_queue->head, struct co_task, head);
//                        task->status = TASK_RUNNING;
//                        rwlock->write_pending--;
//                        rwlock->writer++;
//                        list_del(&task->head);

//                        /*add entry to the task queue*/
//                        add_task_to_work_queue(task);
//                    } else if(rwlock->read_pending > 0) {
//                        task = container_of(rwlock->read_queue->head, struct co_task, head);
//                        task->status = TASK_RUNNING;
//                        rwlock->read_pending--;
//                        rwlock->readers++;
//                        list_del(&task->head);
//                        add_task_to_work_queue(entry);
//                    }
//                }
//            } else {
//                /*bad - pending*/
//            }
//        } else if(pos < rwlock->write_count) {
//            /*the writer*/
//            list_del(&task->head);
//            rwlock->read_count--;
//
//            if(rwlock->read_pending > 0) {
//                /* yield to readers*/
//                task= container_of(rwlock->write_queue->head, struct co_task, head);
//                task->status = TASK_RUNNING;
//
//                rwlock->read_pending--;
//                rwlock->read_count++;
//            } else if(rwlock->write_pending > 0) {
//                /*give the writers a chance*/
//                task= container_of(rwlock->write_queue->head, struct co_task, head);
//                task->status = TASK_RUNNING;
//                rwlock->write_pending--;
//                rwlock->write_count++;
//                /*add entry to the task queue*/
//            }
//        }
//    }
//
//    out: retval = pthread_mutex_unlock(&mutex->mutex);
//    return retval;
//}

