/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * task.c
 *
 *  Created on: Feb 19, 2011
 *      Author: daveds, Erik Nordstrom
 */

#include <serval/list.h>
#include <serval/hash.h>
#include <serval/atomic.h>

#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#define _XOPEN_SOURCE 1
#include <ucontext.h>

#include <common/hashtable.h>
#include <common/debug.h>
#include <libservalctrl/reactor.h>
#include <libservalctrl/task.h>

#define MAX_THREADS 5
#define MAX_CACHED_TASKS 15
#define DEFAULT_STACK_SIZE SIGSTKSZ
static pthread_key_t task_key;
static unsigned int num_threads = MAX_THREADS;

#define LOG_TASK(format, ...) /* LOG_DBG() */

enum task_state {
    TASK_CREATED,
    TASK_INITIALIZED,
    TASK_RUNNING,
    TASK_RESCHEDULE,
    TASK_BLOCKED,
    TASK_FINISHED,
    TASK_DEAD,
};

static char *task_state_str[] = {
    [TASK_CREATED] = "TASK_CREATED",
    [TASK_INITIALIZED] = "TASK_INITIALIZED",
    [TASK_RUNNING] = "TASK_RUNNING",
    [TASK_RESCHEDULE] = "TASK_RESCHEDULE",
    [TASK_BLOCKED] = "TASK_BLOCKED",
    [TASK_FINISHED] = "TASK_FINISHED",
    [TASK_DEAD] = "TASK_DEAD",
};

struct task {
    struct hashelm he;
    unsigned long id;
    struct list_head head;
    unsigned short state;
    unsigned char should_exit;
    void *data;
    task_func_t func;
    struct reactor_block rb;
    pthread_t runner;
    pthread_mutex_t lock;
    pthread_cond_t dead_cond;
    ucontext_t loop_ctx;
    ucontext_t task_ctx;
    unsigned char stack[DEFAULT_STACK_SIZE];
};

/* Should be power of two */
#define HTABLE_MIN_SIZE 32

struct task_set {
    struct list_head free_tasks;
    unsigned int free_count;
    pthread_mutex_t lock;
    unsigned long tot_count;
    struct hashtable table;
};

static struct task_set task_set = {
    .free_tasks = LIST_HEAD_INIT(task_set.free_tasks),
    .free_count = 0,
    .tot_count = 0,
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

struct task_queue {
    struct list_head head;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    unsigned int count;
    unsigned int thread_count;
    volatile unsigned char active;
};

static struct task_queue task_queue = {
    .head = LIST_HEAD_INIT(task_queue.head),
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER,
    .count = 0,
    .thread_count = 0,
    .active = 0
};

static pthread_t *thread_pool;
static struct reactor *reactor;
static void task_schedule(struct task *task);
static void _task_schedule(struct task *task);
static struct task *task_create(void *data, task_func_t tfunc);
static void task_destroy(struct task *task);
void task_hold(struct task *task);
void task_put(struct task *task);

static unsigned int task_hashfn(const void *key)
{
    return *((unsigned int *)key);
}

static int task_equalfn(const hashelm_t *elm, const void *key)
{
    struct task *task = container_of(elm, struct task, he);
    return memcmp(&task->id, key, sizeof(task->id)) == 0;
}

static inline struct task *task_lookup(struct hashtable *table, const void *key)
{
    return hashtable_lookup_entry(table, key, task_hashfn, struct task, he);
}

static void task_set_state(struct task *task, enum task_state state) 
{
    LOG_TASK("Task %lu %s->%s\n", 
            task->id,
            task_state_str[task->state], 
            task_state_str[state]);
    task->state = state;
}

static enum task_state task_get_state(struct task *task)
{
    return (enum task_state)task->state;
}

void task_hold(struct task *task)
{
    hashelm_hold(&task->he);
}

void task_put(struct task *task)
{
    hashelm_put(&task->he);
}

static inline char *print_task(struct task *task, char *buffer, int len)
{
    snprintf(buffer, len, "task %lu thread %lu state %u", task->id,
             (unsigned long)task->runner, task_get_state(task));
    
    return buffer;
}

static void task_runner(void)
{
    struct task *task = pthread_getspecific(task_key);

    LOG_TASK("Starting task %lu on thread %lx\n",
            task->id, pthread_self());
    
    task->func(task->data);

    task_set_state(task, TASK_FINISHED);

    LOG_TASK("task %lu finished on thread %lx\n", task->id, pthread_self());
    
    swapcontext(&task->task_ctx, &task->loop_ctx);
}

void task_freefn(hashelm_t *elm)
{
    struct task *task = container_of(elm, struct task, he);
    task_destroy(task);
}

struct task *task_create(void *data, task_func_t tfunc)
{
    struct task *task = NULL;

    pthread_mutex_lock(&task_set.lock);

    if (list_empty(&task_set.free_tasks)) {

        LOG_TASK("Allocating new task\n");

        /* create a new task */
        task = (struct task *) malloc(sizeof(*task));
        
        if (!task) {
            pthread_mutex_unlock(&task_set.lock);            
            return NULL;
        }
        memset(task, 0, sizeof(*task));
        task_set_state(task, TASK_INITIALIZED);
        task->id = task_set.tot_count++;
        reactor_block_init(&task->rb, -1, 0, NULL, NULL, 0);
        pthread_mutex_init(&task->lock, NULL);
        pthread_cond_init(&task->dead_cond, NULL);
        hashelm_init(&task->he, task_hashfn, task_equalfn, task_freefn);
    } else {
        /* Pick a task off the free list */
        LOG_TASK("Picking task from free list\n");
        task = list_first_entry(&task_set.free_tasks, struct task, head);
        list_del(&task->head);
        task_set.free_count--;
        task_set_state(task, TASK_INITIALIZED);
    }

    pthread_mutex_unlock(&task_set.lock);

    task->data = data;
    task->func = tfunc;
    INIT_LIST_HEAD(&task->head);

    task->task_ctx.uc_link = NULL;
	task->task_ctx.uc_stack.ss_sp = task->stack;
	task->task_ctx.uc_stack.ss_size = DEFAULT_STACK_SIZE;

    if (getcontext(&task->task_ctx)) {
        free(task);
        return NULL;
    }

    /* Add to task table */
    LOG_TASK("Adding task %lu to hash table\n", task->id);
    hashelm_hash(&task_set.table, &task->he, &task->id);

    return task;
}

void task_destroy(struct task *task)
{
    LOG_TASK("destroying task: %lu\n", task->id);
    pthread_mutex_destroy(&task->lock);
    pthread_cond_destroy(&task->dead_cond);
    free(task);
}

int task_join(task_handle_t th)
{
    struct task *task;

    task = task_lookup(&task_set.table, &th);

    if (!task)
        return -1;
    
    task->should_exit = 1;

    /* Join task */
    pthread_mutex_lock(&task->lock);
    
    LOG_TASK("Joining with task %lu\n", task->id);

    while (task_get_state(task) != TASK_DEAD) {
        pthread_cond_wait(&task->dead_cond, &task->lock);
        LOG_TASK("Checking TASK_DEAD condition\n");
    }
    pthread_mutex_unlock(&task->lock);

    LOG_TASK("Task %lu joined\n", task->id);

    task_put(task);
    
    return 0;
}

/* Called with task->lock held */
static void _task_release(struct task *task)
{
    if (task == NULL)
        return;

    LOG_TASK("releasing task %lu\n", task->id);                
    
    /* Remove the task from the task table */
    task_hold(task);
    LOG_TASK("Removing task %lu from hash table\n", task->id);
    hashelm_unhash(&task_set.table, &task->he);
    
    /* Synchronize around the TASK_DEAD state for other threads that
     * are joining on this task */
    task_set_state(task, TASK_DEAD);
    LOG_TASK("Task %lu broadcast TASK_DEAD condition\n", task->id);
    pthread_cond_broadcast(&task->dead_cond);

    pthread_mutex_lock(&task_set.lock);

    if (task_set.free_count < MAX_CACHED_TASKS) {
        task->data = NULL;
        task->func = NULL;
        task->runner = (pthread_t) 0;
        list_add_tail(&task->head, &task_set.free_tasks);
        task_set.free_count++;
    } else {
        task_put(task);
    }
    pthread_mutex_unlock(&task_set.lock);

    pthread_mutex_lock(&task_queue.lock);

    if (hashtable_count(&task_set.table) == 0) {
        task_queue.active = 0;
        LOG_TASK("<<<<<<>>>>>>> No tasks left in hashtable,"
                " raising exit condition\n");
        pthread_cond_broadcast(&task_queue.cond);
    }

    pthread_mutex_unlock(&task_queue.lock);
}

static void reactor_reschedule(void *target)
{
    struct task *task = (struct task *) target;
    pthread_mutex_lock(&task->lock);
    if (task_get_state(task) == TASK_BLOCKED) {
        LOG_TASK("Task %lu unblocks\n", task->id);
        task_set_state(task, TASK_RUNNING);
    }
    _task_schedule(task);
    pthread_mutex_unlock(&task->lock);
}

/* Main task execution/scheduling loop for worker threads */
static void task_thread_loop(void)
{   
    struct task *task;

    LOG_TASK("Thread %lx running task loop\n", 
            pthread_self());

    pthread_mutex_lock(&task_queue.lock);

    task_queue.thread_count++;

    while (task_queue.active) {
        while (list_empty(&task_queue.head)) {
            pthread_cond_wait(&task_queue.cond, &task_queue.lock);

            if (!task_queue.active)
                goto out;
        }

        /* Pull a task off the queue and run it, or resume. */
        task = list_first_entry(&task_queue.head, struct task, head);
        list_del(&task->head);
        INIT_LIST_HEAD(&task->head);
        task_queue.count--;
        task->runner = pthread_self();
        pthread_mutex_unlock(&task_queue.lock);
        
        /* LOG_TASK("Thread %lx acquired task %lu\n", 
           pthread_self(), task->id); */

        /* Make sure this task is marked as unqueued and scheduled on
           the current thread. */
        pthread_mutex_lock(&task->lock);

        /* Save the task pointer on the thread's TLS */
        pthread_setspecific(task_key, task);
        
        LOG_TASK("Thread %lx running task %lu\n",
                pthread_self(), task->id);
        
        switch (task_get_state(task)) {
        case TASK_INITIALIZED:
            /* This is a new task, first time we run it. */
            makecontext(&task->task_ctx, task_runner, 1);
            /* Fall through */
        case TASK_RESCHEDULE:
            task_set_state(task, TASK_RUNNING);
            /* Fall through */
        case TASK_RUNNING:
            /* Switch to task context, which will call the
             * task_runner() function (or resume the previously
             * saved task context), and save the current context
             * so that we return here when the task yields. */
            pthread_mutex_unlock(&task->lock);
            swapcontext(&task->loop_ctx, &task->task_ctx);
            pthread_mutex_lock(&task->lock);

            if (task_get_state(task) == TASK_FINISHED) {
                LOG_TASK("Task %lu finished, releasing\n", task->id);
                _task_release(task);
                pthread_mutex_unlock(&task->lock);
                task = NULL;
            } else {
                /* Task yielded, run next task */
                LOG_TASK("Task %lu yielded on thread=%lx\n", 
                        task->id, pthread_self());
                pthread_mutex_unlock(&task->lock);
            }
            break;
        default:
            LOG_TASK("Task %lu in bad state %u\n", 
                    task->id, task_get_state(task));
            pthread_mutex_unlock(&task->lock);
            break;
        case TASK_BLOCKED:
            LOG_TASK("Task %lu in BLOCKED state\n", task->id);
            if (task->should_exit) {
                LOG_TASK("Task %lu should exit\n", task->id);
                task_set_state(task, TASK_RESCHEDULE);
            }
            pthread_mutex_unlock(&task->lock);
            break;
        }
        
        pthread_mutex_lock(&task_queue.lock);

        if (task) {
            task->runner = 0;

            /* Another thread returned an event that the task was
             * interested in before the task thread managed to
             * completely switch to another task. In this case, the
             * other thread does not reschedule the task (since it was
             * still "running" when the event happened), and instead
             * the runner thread will reschedule the task. */

            if ((task_get_state(task) == TASK_RESCHEDULE || 
                 task->should_exit) && list_empty(&task->head)) {
                LOG_TASK("task %lu rescheduling itself\n", task->id);
                list_add_tail(&task->head, &task_queue.head);
            }
        }
        pthread_setspecific(task_key, NULL);
    }
out:
    
    LOG_TASK("############ Thread %lx end of loop\n", pthread_self());
    task_queue.thread_count--;
    pthread_mutex_unlock(&task_queue.lock);
}

static void *task_thread_start(void *data)
{
    int retval;
    sigset_t mask;

    /* Mask appropriate signals */

    sigemptyset(&mask);
    sigaddset(&mask, SIGPIPE);

    retval = pthread_sigmask(SIG_BLOCK, &mask, NULL);

    if (retval) {
        fprintf(stderr, "Could not set thread signal mask: %s",
                strerror(retval));
    
    } else {
        task_thread_loop();
    }
    return NULL;
}

int task_libinit(void)
{
    unsigned int i;
    task_handle_t th;

#if defined(OS_LINUX) || defined(OS_BSD)
    long num_cpu;
    
    num_cpu = sysconf(_SC_NPROCESSORS_ONLN);
    
    if (num_cpu > 0 && num_cpu < num_threads) {
        /* Create one more thread than number of online CPUs */
        num_threads = num_cpu + 1;
    }
#endif

    LOG_TASK("Creating %u threads in pool\n",
            num_threads);

    thread_pool = malloc(sizeof(*thread_pool) * num_threads);

    if (!thread_pool)
        return -1;

    pthread_key_create(&task_key, NULL);    

    if (hashtable_init(&task_set.table, HTABLE_MIN_SIZE))
        return -1;

    reactor = reactor_create();

    if (!reactor) {
        free(thread_pool);
        pthread_key_delete(task_key);
        hashtable_fini(&task_set.table);
        return -1;
    }

    /*set the queue to active */
    task_queue.active = 1;

    /* add the poll task */
    if (task_add(&th, reactor_loop, reactor) == -1) {
        reactor_free(reactor);
        free(thread_pool);
        pthread_key_delete(task_key);
        hashtable_fini(&task_set.table);
        return -1;
    }

    for (i = 0; i < num_threads; i++) {
        if (pthread_create(&thread_pool[i], NULL, task_thread_start, NULL)) {
            LOG_ERR("Could not create thread # %u\n", i);
        }
    }
    
    return 0;
}

static void task_should_exit(struct hashelm *e)
{
    struct task *task = container_of(e, struct task, he);
    task->should_exit = 1;
}

void task_libfini(void)
{
    int i, ret = 0;

    LOG_TASK("Cleaning up tasks\n");

    reactor_stop(reactor);

    hashtable_for_each(&task_set.table, task_should_exit);

    for (i = 0; i < num_threads; i++) {
        LOG_TASK("joining with thread %lx\n", 
                thread_pool[i]);

        ret = pthread_join(thread_pool[i], NULL);

        if (ret) {
            LOG_ERR("Could not join killed thread: %s\n", strerror(ret));
        }
    }

    LOG_TASK("All threads joined\n");

    free(thread_pool);

    /* After all threads have joined, it should be safe to access the
     * tables without locking. However, this assumes some other thread
     * is not calling a task function that accesses the tables while
     * we are finalizing. Therefore, just lock to be sure. */

    pthread_mutex_lock(&task_set.lock);

    hashtable_fini(&task_set.table);

    while (!list_empty(&task_set.free_tasks)) {
        struct task *task = list_first_entry(&task_set.free_tasks, 
                                             struct task, head);
        list_del(&task->head);
        task_put(task);
    }

    reactor_free(reactor);

    pthread_key_delete(task_key);
    pthread_mutex_unlock(&task_set.lock);

    pthread_mutex_destroy(&task_queue.lock);
    pthread_mutex_destroy(&task_set.lock);
    pthread_cond_destroy(&task_queue.cond);
}

/* Called with task->lock held */
static void _task_schedule(struct task *task)
{
    if (task == NULL || !task_queue.active)
        return;

    pthread_mutex_lock(&task_queue.lock);

    if (task->runner) {
        /* Thread still associated with this task, set state to
         * TASK_RESCHEDULE to let the runner thread itself reschedule
         * the task. */
        LOG_TASK("Letting task %lu reschedule itself\n", task->id);
        task_set_state(task, TASK_RESCHEDULE);
    } else { 
        if (list_empty(&task->head)) {
            int should_notify;
            /* Only schedule if not already in the queue and not executing */
            LOG_TASK("Scheduling task %lu\n", task->id);
            list_add_tail(&task->head, &task_queue.head);
            
            should_notify = !(task_queue.count) && task_queue.thread_count > 0;
        
            task_queue.count++;
            
            if (should_notify) {
                LOG_TASK("Notifiying queue (cond_broadcast)\n");
                pthread_cond_broadcast(&task_queue.cond);
            }
        } else {
            LOG_TASK("Task %lu already scheduled\n", task->id);
        }
    }
    pthread_mutex_unlock(&task_queue.lock);

    LOG_TASK("Task %lu scheduled!\n", task->id);
}

static void task_schedule(struct task *task)
{
        pthread_mutex_lock(&task->lock);
        _task_schedule(task);
        pthread_mutex_unlock(&task->lock);
}

int task_cond_init(task_cond_t *cond)
{
    assert(cond);
    INIT_LIST_HEAD(&cond->wait_queue);
    cond->wait_count = 0;
    pthread_mutex_init(&cond->lock, NULL);
    return 0;
}

int task_cond_destroy(task_cond_t *cond)
{
    assert(cond);
    if (cond->wait_count > 0) {
        return EBUSY;
    }
    pthread_mutex_destroy(&cond->lock);
    return 0;
}

int task_cond_wait(task_cond_t *cond, pthread_mutex_t *mutex)
{    
    struct task *task = pthread_getspecific(task_key);

    pthread_mutex_lock(&cond->lock);
    list_add_tail(&task->head, &cond->wait_queue);
    cond->wait_count++;
    pthread_mutex_unlock(&cond->lock);

    pthread_mutex_unlock(mutex);

    /* yield to the scheduler */    
    swapcontext(&task->task_ctx, &task->loop_ctx);

    pthread_mutex_lock(mutex);

    return 0;
}

int task_cond_notify(task_cond_t *cond)
{
    struct task *task;

    assert(cond);

    pthread_mutex_lock(&cond->lock);

    if (list_empty(&cond->wait_queue))
        return 0;

    task = list_first_entry(&cond->wait_queue, struct task, head);
    list_del(&task->head);
    cond->wait_count--;
    pthread_mutex_unlock(&cond->lock);

    task_schedule(task);

    return 0;
}

int task_add(task_handle_t *handle, task_func_t tfunc, void *data)
{
    struct task *task;

    if (!tfunc || !handle)
        return -1;

    task = task_create(data, tfunc);

    if (task) {
        /* add to work queue */
        task_schedule(task);

        *handle = task->id;
        /* Task protected by refcount as long as it is in the hash
         * table */
        task_put(task);
        return 0;
    }
    return -1;
}

int task_add_delayed(task_handle_t *handle, task_func_t tfunc, 
                     void *data, unsigned long millisecs)
{
    struct task *task;

    if (!tfunc || !handle)
        return -1;

    task = task_create(data, tfunc);

    if (task) {
        pthread_mutex_lock(&task->lock);

        reactor_block_init(&task->rb, -1, 0, 
                           reactor_reschedule, 
                           data, millisecs); 
        reactor_add(reactor, &task->rb);
        *handle = task->id;
        task_set_state(task, TASK_BLOCKED);
        pthread_mutex_unlock(&task->lock);

        /* Task protected by refcount as long as it is in the hash
         * table */
        task_put(task);
        return 0;
    }
    return -1;
}

int task_cancel(task_handle_t handle)
{
    struct task *task;
    
    task = task_lookup(&task_set.table, &handle);

    if (!task) {
        LOG_ERR("Could not find task with handle %lu\n", handle);
        return -1;
    }

    LOG_TASK("Marking task %lu for exit\n", task->id);

    task->should_exit = 1;
    
    pthread_mutex_lock(&task->lock);

    if (task->state == TASK_BLOCKED) {
        LOG_TASK("Task %lu is blocked, unblocking\n", task->id);
        reactor_remove(reactor, &task->rb);
    } else {
        LOG_TASK("Task %lu is not blocked\n", task->id);
    }
    pthread_mutex_unlock(&task->lock);

    task_put(task);
    
    return 0;
}

int task_count(void)
{
    return atomic_read(&task_set.table.count);
}

int task_free_count(void)
{
    int count = 0;
    pthread_mutex_lock(&task_set.lock);
    count = task_set.free_count;
    pthread_mutex_unlock(&task_set.lock);
    return count;
}

int task_block(int fd, unsigned short flags)
{
    struct task *task = pthread_getspecific(task_key);

    if (task->should_exit)
        return -1;

    pthread_mutex_lock(&task->lock);

    if (task->state == TASK_RUNNING || 
        task->state == TASK_RESCHEDULE) {
        reactor_block_init(&task->rb, fd, flags, 
                           reactor_reschedule, task, -1);
        reactor_add(reactor, &task->rb);
        
        LOG_TASK("task %lu yields on blocking\n", task->id);
        task_set_state(task, TASK_BLOCKED);
        
        pthread_mutex_unlock(&task->lock);
        swapcontext(&task->task_ctx, &task->loop_ctx);
        LOG_TASK("task %lu resumes from blocking\n", task->id);    
    } else {
        pthread_mutex_unlock(&task->lock);
    }        
    return 0;
}

void task_yield(void)
{
    struct task *task = pthread_getspecific(task_key);

    task_schedule(task);

    LOG_TASK("task %lu yields\n", task->id);

    swapcontext(&task->task_ctx, &task->loop_ctx); 
}

void task_sleep(unsigned int ms)
{
    struct task *task = pthread_getspecific(task_key);
    
    pthread_mutex_lock(&task->lock);

    if (task->state == TASK_RUNNING || 
        task->state == TASK_RESCHEDULE) {
        reactor_block_init(&task->rb, -1, 0, reactor_reschedule, task, ms);    
        reactor_add(reactor, &task->rb);

        task_set_state(task, TASK_BLOCKED);
        pthread_mutex_unlock(&task->lock);

        swapcontext(&task->task_ctx, &task->loop_ctx); 

        pthread_mutex_lock(&task->lock);
    } 
    pthread_mutex_unlock(&task->lock);
}

int task_kill(task_handle_t handle, int signal)
{
    struct task *task;
    int retval = 0;

    task = task_lookup(&task_set.table, &handle);

    if (!task)
        return -1;

    /* This may be strange, but for now, only deliver signals to
     * running tasks */
    if (task_get_state(task) == TASK_RUNNING) {
        retval = pthread_kill(task->runner, signal);

    } else {
        /* TODO - this should also handle cond wait tasks as well - move to active queue with pending signal
         * for lock states, this would require setting the task state properly, i.e. TASK_LOCK_WAIT for
         * pthread_mutex_lock, etc
         * */
        retval = ESRCH;
    }

    task_put(task);

    return retval;
}
