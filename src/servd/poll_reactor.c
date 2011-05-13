/*
 * SelectReactor.cpp
 *
 *  Created on: Oct 25, 2009
 *      Author: daveds
 */

#include "poll_reactor.h"
#include "serval/list.h"

#include <glib.h>
#include <errno.h>
#include <stdio.h>
#include <serval/list.h>
#include <fcntl.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <sys/epoll.h>

struct reactor_task {
    void* target;
    reactor_exec exec;
};

//file descriptor interest node: fd and execution context
//note: doubly-linked list node
struct fdtask {
    int fd;
    struct reactor_task read_task;
    struct reactor_task write_task;
    struct reactor_task error_task;
};

#define fd_can_exec(fdt) (fdt->read_task.exec || fdt->write_task.exec || fdt->error_task.exec)
#define fd_can_read(fdt) (fdt->read_task.exec)
#define fd_can_write(fdt) (fdt->write_task.exec)
#define fd_can_handle_error(fdt) (fdt->error_task.exec)

struct timeout_entry {
    struct list_head head;
    long long key;
    int count;
};

struct timeout_node {
    struct list_head head;
    struct reactor_task task;
};

static int execute_task(struct poll_reactor_ds* reactor, struct fdtask* task, int flags);
static int execute_timeout(struct poll_reactor_ds* reactor, long long timeout);
static int generate_epoll_ctl_flags(struct poll_reactor_ds* reactor, struct fdtask* task);
static int register_interest(struct poll_reactor_ds* reactor, int fd, struct fdtask* task, int op);
static void register_all_interest(struct poll_reactor_ds* reactor);
static void unregister_all_interest(struct poll_reactor_ds* reactor);

static int timeout_comp(const void* a, const void* b, void* user_data) {
    if(a == b) {
        return 0;
    }

    struct timeout_entry* ea = (struct timeout_entry*) a;
    struct timeout_entry* eb = (struct timeout_entry*) b;

    if(ea->key < eb->key) {
        return -1;
    }

    if(ea->key > eb->key) {
        return 1;
    }

    return 0;

}

void pr_add_timeout(struct poll_reactor_ds* reactor, time_t msec, reactor_exec exec, void* target) {
    if(exec == NULL || target == NULL || msec < 0) {
        return;
    }

    int signal_poll_thread = FALSE;

    pthread_mutex_lock(&reactor->mutex);

    struct timeout_entry le;
    struct timeout_entry* entry;

    struct timeout_node* node = (struct timeout_node*) malloc(sizeof(*node));
    bzero(node, sizeof(*node));
    node->task.target = target;
    node->task.exec = exec;

    le.key = get_current_time_ms() + msec;

    GSequenceIter* iter = g_sequence_search(reactor->timeout_seq, &le, timeout_comp, NULL);

    if(g_sequence_iter_is_end(iter) || ((entry = (struct timeout_entry*) g_sequence_get(iter))
            && entry->key != le.key)) {
        entry = (struct timeout_entry*) malloc(sizeof(*entry));
        bzero(entry, sizeof(*entry));
        INIT_LIST_HEAD(&entry->head);
        entry->key = le.key;

        iter = g_sequence_insert_sorted(reactor->timeout_seq, entry, timeout_comp, NULL);
        //LOG_DBG("added new timeout - is it at the beginning? %i\n", g_sequence_iter_is_begin(iter));
    }

    list_add_tail(&node->head, &entry->head);
    entry->count++;

    LOG_DBG("add timeout, timeout: %llu current timeout: %llu\n", le.key, reactor->current_timeout);

    if(reactor->current_timeout <= 0 || le.key < reactor->current_timeout) {
        //reschedule the timeout TODO - for multi-threaded - interrupt
        reactor->current_timeout = le.key;
        signal_poll_thread = reactor->state == REACTOR_STARTED;
    }

    pthread_mutex_unlock(&reactor->mutex);
    if(signal_poll_thread) {
        task_kill(reactor->poll_task, SIGINT);
    }
}

int pr_cancel_timeout(struct poll_reactor_ds* reactor, reactor_exec exec, void* target) {
    assert(reactor);
    if(exec == NULL) {
        return EINVAL;
    }

    int retval = -1;
    /*scan through all the timeouts to find the task*/
    pthread_mutex_lock(&reactor->mutex);
    struct timeout_entry* entry;
    struct timeout_node* node;
    struct timeout_node* temp;
    GSequenceIter* iter = g_sequence_get_begin_iter(reactor->timeout_seq);

    while(!g_sequence_iter_is_end(iter)) {
        entry = g_sequence_get(iter);
        if(entry == NULL) {
            /*error*/
            LOG_ERR("Null reactor timeout entry!\n");
        } else {
            list_for_each_entry_safe(node, temp, &entry->head, head) {
                if(node->task.target == target && node->task.exec == exec) {
                    list_del(&node->head);
                    entry->count--;
                    if(entry->count == 0) {
                        g_sequence_remove(iter);
                    }
                    retval = 0;
                    LOG_DBG("Canceled existing timeout\n");
                    goto out;
                }
            }
        }
        iter = g_sequence_iter_next(iter);
    }

    out: pthread_mutex_unlock(&reactor->mutex);
    return retval;
}

int pr_is_waiting(struct poll_reactor_ds* reactor, reactor_exec exec, void* target) {
    assert(reactor);
    if(exec == NULL) {
        return EINVAL;
    }

    int retval = FALSE;
    /*scan through all the timeouts to find the task*/
    pthread_mutex_lock(&reactor->mutex);
    struct timeout_entry* entry;
    struct timeout_node* node;
    struct timeout_node* temp;
    GSequenceIter* iter = g_sequence_get_begin_iter(reactor->timeout_seq);

    while(!g_sequence_iter_is_end(iter)) {
        entry = g_sequence_get(iter);
        if(entry == NULL) {
            /*error*/
            LOG_ERR("Null reactor timeout entry!\n");
        } else {
            list_for_each_entry_safe(node, temp, &entry->head, head) {
                if(node->task.target == target) {
                    retval = TRUE;
                    goto out;
                }
            }
        }
        iter = g_sequence_iter_next(iter);
    }

    out: pthread_mutex_unlock(&reactor->mutex);
    return retval;
}

static int execute_timeout(struct poll_reactor_ds* reactor, long long timeout) {

    if(g_sequence_get_length(reactor->timeout_seq) == 0) {
        return 0;
    }

    //LOG_DBG("executing timeout with time: %llu timeout seq len: %i\n", timeout, g_sequence_get_length(reactor->timeout_seq));

    GSequenceIter* iter = g_sequence_get_begin_iter(reactor->timeout_seq);
    GSequenceIter* itemp;

    int count = 0;
    struct timeout_entry* entry;
    struct timeout_node* node;
    struct timeout_node* temp;

    while(!g_sequence_iter_is_end(iter)) {
        entry = (struct timeout_entry*) g_sequence_get(iter);

        if(entry->key <= timeout) {
            /*trigger - memory is passed on*/
            //LOG_DBG("preparing to execute %i tasks in task list for time: %llu iter pos: %i\n", entry->count, timeout, g_sequence_iter_get_position(iter));

            list_for_each_entry_safe(node, temp, &entry->head, head) {
                node->task.exec(node->task.target);
                list_del(&node->head);
                free(node);
            }

            count += entry->count;

            itemp = iter;
            iter = g_sequence_iter_next(iter);
            g_sequence_remove(itemp);
            free(entry);
        } else {
            break;
        }

    }

    if(g_sequence_get_length(reactor->timeout_seq) == 0) {
        reactor->current_timeout = -1;
    } else {
        iter = g_sequence_get_begin_iter(reactor->timeout_seq);
        entry = (struct timeout_entry*) g_sequence_get(iter);
        reactor->current_timeout = entry->key;
    }

    return count;
}

void pr_clear(struct poll_reactor_ds* reactor) {

    pthread_mutex_lock(&reactor->mutex);

    if(reactor->task_map == NULL) {
        goto out;
    }

    unregister_all_interest(reactor);

    if(g_sequence_get_length(reactor->timeout_seq) == 0) {
        goto out;
    }

    GSequenceIter* iter = g_sequence_get_begin_iter(reactor->timeout_seq);
    GSequenceIter* itemp;

    struct timeout_entry* entry;
    struct list_head * pos;
    struct list_head * temp;
    while(!g_sequence_iter_is_end(iter)) {
        entry = (struct timeout_entry*) g_sequence_get(iter);

        list_for_each_safe(pos, temp, &entry->head) {
            free(pos);
        }

        itemp = iter;
        iter = g_sequence_iter_next(iter);
        g_sequence_remove(itemp);
        free(entry);
    }

    GHashTableIter titer;
    g_hash_table_iter_init(&titer, reactor->task_map);
    struct fdtask* fdt;
    while(g_hash_table_iter_next(&titer, NULL, (void**) &fdt)) {
        if(fdt != NULL) {
            g_hash_table_iter_remove(&titer);
            free(fdt);
        }
    }

    out: pthread_mutex_unlock(&reactor->mutex);
}

void pr_set_read(struct poll_reactor_ds* reactor, int fd, reactor_exec exec, void* target) {
    assert(exec);

    if(fd <= 0) {
        return;
    }

    pthread_mutex_lock(&reactor->mutex);
    struct fdtask* task = g_hash_table_lookup(reactor->task_map, &fd);
    int op = EPOLL_CTL_ADD;

    if(task == NULL) {
        task = (struct fdtask*) malloc(sizeof(*task));
        bzero(task, sizeof(*task));
        task->fd = fd;

        g_hash_table_insert(reactor->task_map, &task->fd, task);
        reactor->read_count++;
    } else {
        if(!fd_can_read(task)) {
            reactor->read_count++;
        }
        op = EPOLL_CTL_MOD;
    }

    task->read_task.exec = exec;
    task->read_task.target = target;

    int retval = register_interest(reactor, fd, task, op);

    if(retval) {
        LOG_ERR("Could not register read interest for fd %i: %s\n", fd, strerror(errno));
    }

    pthread_mutex_unlock(&reactor->mutex);
}

void pr_set_write(struct poll_reactor_ds* reactor, int fd, reactor_exec exec, void* target) {
    assert(reactor);

    if(fd <= 0) {
        return;
    }

    pthread_mutex_lock(&reactor->mutex);
    struct fdtask* task = g_hash_table_lookup(reactor->task_map, &fd);
    int op = EPOLL_CTL_ADD;

    if(task == NULL) {
        task = (struct fdtask*) malloc(sizeof(*task));
        bzero(task, sizeof(*task));
        task->fd = fd;

        g_hash_table_insert(reactor->task_map, &task->fd, task);
        reactor->write_count++;
    } else {
        if(!fd_can_write(task)) {
            reactor->write_count++;
        }

        op = EPOLL_CTL_MOD;
    }

    task->write_task.exec = exec;
    task->write_task.target = target;

    int retval = register_interest(reactor, fd, task, op);

    if(retval) {
        LOG_ERR("Could not register write interest for fd %i: %s\n", fd, strerror(errno));
    }

    pthread_mutex_unlock(&reactor->mutex);
}

void pr_set_error(struct poll_reactor_ds* reactor, int fd, reactor_exec exec, void* target) {
    assert(reactor);

    if(fd <= 0) {
        return;
    }

    pthread_mutex_lock(&reactor->mutex);
    struct fdtask* task = g_hash_table_lookup(reactor->task_map, &fd);
    int op = EPOLL_CTL_ADD;

    if(task == NULL) {
        task = (struct fdtask*) malloc(sizeof(*task));
        bzero(task, sizeof(*task));
        task->fd = fd;

        g_hash_table_insert(reactor->task_map, &task->fd, task);
        reactor->error_count++;
    } else {
        if(!fd_can_handle_error(task)) {
            reactor->error_count++;
        }

        op = EPOLL_CTL_MOD;

    }
    task->error_task.exec = exec;
    task->error_task.target = target;

    int retval = register_interest(reactor, fd, task, op);

    if(retval) {
        LOG_ERR("Could not register error interest for fd %i: %s\n", fd, strerror(errno));
    }

    pthread_mutex_unlock(&reactor->mutex);
}

void pr_set_interest(struct poll_reactor_ds* reactor, int fd, reactor_exec rexec, void* rdata,
        reactor_exec wexec, void* wdata, reactor_exec eexec, void* edata) {
    assert(reactor);

    if(fd <= 0) {
        return;
    }

    pthread_mutex_lock(&reactor->mutex);
    struct fdtask* task = g_hash_table_lookup(reactor->task_map, &fd);
    int op = EPOLL_CTL_ADD;

    if(task == NULL) {
        task = (struct fdtask*) malloc(sizeof(*task));
        bzero(task, sizeof(*task));
        task->fd = fd;

        g_hash_table_insert(reactor->task_map, &task->fd, task);

    } else {
        op = EPOLL_CTL_MOD;

    }

    if(!fd_can_read(task)) {
        reactor->read_count++;
    }
    task->read_task.exec = rexec;
    task->read_task.target = rdata;
    if(!fd_can_write(task)) {
        reactor->write_count++;
    }

    task->write_task.exec = wexec;
    task->write_task.target = wdata;

    if(!fd_can_handle_error(task)) {
        reactor->error_count++;
    }

    task->error_task.exec = eexec;
    task->error_task.target = edata;

    int retval = register_interest(reactor, fd, task, op);

    if(retval) {
        LOG_ERR("Could not registerinterest for fd %i: %s\n", fd, strerror(errno));
    }

    pthread_mutex_unlock(&reactor->mutex);
}

void* pr_clear_read(struct poll_reactor_ds* reactor, int fd) {

    pthread_mutex_lock(&reactor->mutex);
    struct fdtask* task = g_hash_table_lookup(reactor->task_map, &fd);
    void* target = NULL;
    if(task == NULL || !fd_can_read(task)) {
        goto out;
    }

    int op = EPOLL_CTL_MOD;

    target = task->read_task.target;
    task->read_task.target = NULL;
    task->read_task.exec = NULL;

    reactor->read_count--;
    if(!fd_can_exec(task)) {
        /*remove it*/
        op = EPOLL_CTL_DEL;
        g_hash_table_remove(reactor->task_map, &fd);
        free(task);
    }

    int retval = register_interest(reactor, fd, task, op);

    if(retval) {
        LOG_ERR("Could not clear read interest for fd %i: %s\n", fd, strerror(errno));
    }

    out: pthread_mutex_unlock(&reactor->mutex);

    return target;
}

void* pr_clear_write(struct poll_reactor_ds* reactor, int fd) {

    pthread_mutex_lock(&reactor->mutex);
    struct fdtask* task = g_hash_table_lookup(reactor->task_map, &fd);
    void* target = NULL;

    if(task == NULL || !fd_can_write(task)) {
        goto out;

    }
    int op = EPOLL_CTL_MOD;

    target = task->write_task.target;
    task->write_task.target = NULL;
    task->write_task.exec = NULL;

    reactor->write_count--;
    if(!fd_can_exec(task)) {
        /*remove it*/
        op = EPOLL_CTL_DEL;
        g_hash_table_remove(reactor->task_map, &fd);
        free(task);
    }

    int retval = register_interest(reactor, fd, task, op);

    if(retval) {
        LOG_ERR("Could not clear write interest for fd %i: %s\n", fd, strerror(errno));
    }

    out: pthread_mutex_unlock(&reactor->mutex);
    return target;
}

void* pr_clear_error(struct poll_reactor_ds* reactor, int fd) {

    pthread_mutex_lock(&reactor->mutex);
    struct fdtask* task = g_hash_table_lookup(reactor->task_map, &fd);
    void* target = NULL;
    if(task == NULL || !fd_can_handle_error(task)) {
        goto out;

    }
    int op = EPOLL_CTL_MOD;
    target = task->error_task.target;
    task->error_task.target = NULL;
    task->error_task.exec = NULL;

    reactor->error_count--;
    if(!fd_can_exec(task)) {
        /*remove it*/
        op = EPOLL_CTL_DEL;
        g_hash_table_remove(reactor->task_map, &fd);
        free(task);
    }

    int retval = register_interest(reactor, fd, task, op);

    if(retval) {
        LOG_ERR("Could not clear error interest for fd %i: %s\n", fd, strerror(errno));
    }

    out: pthread_mutex_unlock(&reactor->mutex);
    return target;
}

int pr_finalize(struct poll_reactor_ds* reactor) {
    assert(reactor);
    pr_clear(reactor);

    pthread_mutex_lock(&reactor->mutex);
    if(reactor->task_map) {
        g_hash_table_destroy(reactor->task_map);
        reactor->task_map = NULL;
    }
    if(reactor->timeout_seq) {
        g_sequence_free(reactor->timeout_seq);
        reactor->timeout_seq = NULL;
    }

    if(reactor->poll_fd) {
        close(reactor->poll_fd);
        reactor->poll_fd = 0;
    }
    pthread_mutex_unlock(&reactor->mutex);

    pthread_mutex_destroy(&reactor->mutex);
    return 0;
}

int pr_initialize(struct poll_reactor_ds* reactor) {
    reactor->state = REACTOR_INITIALIZED;
    reactor->timeout_seq = g_sequence_new(NULL);
    reactor->task_map = g_hash_table_new(g_int_hash, g_int_equal);

    int retval = pthread_mutex_init(&reactor->mutex, NULL);

    if(retval) {
        LOG_ERR("Could not initialize reactor mutex: %s", strerror(retval));
        return -1;
    }

    reactor->poll_fd = epoll_create(FD_CLOEXEC);

    if(reactor->poll_fd < 0) {
        LOG_ERR("Could not create epoll file descriptor: %s", strerror(errno));
        return -1;
    }

    return 0;

}

void pr_start(struct poll_reactor_ds* reactor) {
    if(reactor->state != REACTOR_INITIALIZED) {
        //error
    }

    /*only one thread should ever be executing the poll loop!*/

    reactor->state = REACTOR_STARTED;

    pthread_mutex_lock(&reactor->mutex);
    register_all_interest(reactor);
    pthread_mutex_unlock(&reactor->mutex);

    struct epoll_event events[reactor->max_events];
    bzero(events, reactor->max_events * sizeof(struct epoll_event));

    int num_fds = 0;
    long long delta = 0;
    struct fdtask* task = NULL;
    int retval = 0;

    LOG_DBG("starting the poll reactor\n");

    /* TODO - spin (wait time = 0) + yield a few times before fully waiting to allow the thread
     * to work on other tasks before finally blocking on a timeout or fd
     */

    while(reactor->state == REACTOR_STARTED) {

        delta = reactor->current_timeout - resolve_current_time_ms();
        //printf("delta: %lli current timeout: %lli current time: %lli\n", delta,
        //        reactor->current_timeout, resolve_current_time_ms());
        if(delta < 0 || delta > reactor->default_timeout * 1000) {
            delta = reactor->default_timeout * 1000;
        }

        delta++;

        LOG_DBG("polling with timeout: %lli, read interest: %i, write interest: %i, max events: %i\n", delta,
                reactor->read_count, reactor->write_count, reactor->max_events);

        /* TODO might need to differentiate between poll events and lingering "ready" state
         * for active fd's to avoid starvation*/
        num_fds = epoll_wait(reactor->poll_fd, events, reactor->max_events, (int) delta);
        //LOG_DBG("poll event or timeout: %i\n", num_fds);
        pthread_mutex_lock(&reactor->mutex);
        if(num_fds < 0) {
            if(errno == EINTR) {
                //first execute timeouts
                //LOG_DBG("poll interrupted: current time: %lli current timeout: %llu thread %i\n", get_current_time_ms(), reactor->current_timeout, (int) pthread_self());
                execute_timeout(reactor, get_current_time_ms());
                pthread_mutex_unlock(&reactor->mutex);
                continue;
            } else {
                LOG_ERR("poll error: %s\n", strerror(errno));
            }
        }

        //first execute timeouts
        execute_timeout(reactor, get_current_time_ms());

        /*interest must be re-registered - say via task_block, otherwise, the same task could be scheduled multiple times on the queue*/
        int i = 0;
        //printf("executing fd tasks: %i\n", num_fds);
        for(; i < num_fds; i++) {
            //all the triggered events
            task = (struct fdtask*) events[i].data.ptr;
            //printf("fd %i interest %i triggered with data: %0x\n", task->fd, events[i].events,
            //        (int) events[i].data.ptr);
            retval = execute_task(reactor, task, events[i].events);

            if(retval < 0) {
                //error TODO
            }
        }

        pthread_mutex_unlock(&reactor->mutex);
    }

    LOG_DBG("Poll reactor loop terminated\n");

}

void pr_stop(struct poll_reactor_ds* reactor) {
    pthread_mutex_lock(&reactor->mutex);
    reactor->state = REACTOR_STOPPED;
    unregister_all_interest(reactor);
    pthread_mutex_unlock(&reactor->mutex);

}

struct poll_reactor_ds* create_poll_reactor(int max_events, int def_timeout) {
    struct poll_reactor_ds* reactor = (struct poll_reactor_ds*) malloc(sizeof(*reactor));
    bzero(reactor, sizeof(*reactor));

    if(def_timeout > 0) {
        reactor->default_timeout = def_timeout;
    } else {
        reactor->default_timeout = DEFAULT_POLL_TIMEOUT;
    }

    if(max_events > 0) {
        reactor->max_events = max_events;
    } else {
        reactor->max_events = MAX_POLL_EVENTS;
    }

    return reactor;
}

static void unregister_all_interest(struct poll_reactor_ds* reactor) {

    if(reactor->state == REACTOR_STARTED) {
        struct fdtask* task = NULL;

        GHashTableIter iter;
        g_hash_table_iter_init(&iter, reactor->task_map);

        while(g_hash_table_iter_next(&iter, NULL, (void**) &task)) {
            if(task != NULL && fd_can_exec(task)) {
                epoll_ctl(reactor->poll_fd, EPOLL_CTL_DEL, task->fd, NULL);
            }
        }

    }
}

static void register_all_interest(struct poll_reactor_ds* reactor) {

    if(reactor->state == REACTOR_STARTED) {
        struct fdtask* task = NULL;
        struct epoll_event event;
        GHashTableIter iter;
        g_hash_table_iter_init(&iter, reactor->task_map);

        while(g_hash_table_iter_next(&iter, NULL, (void**) &task)) {

            if(task != NULL && fd_can_exec(task)) {
                bzero(&event, sizeof(event));
                event.events = generate_epoll_ctl_flags(reactor, task);
                event.data.ptr = task;
                //remove it from the fd poll
                epoll_ctl(reactor->poll_fd, EPOLL_CTL_ADD, task->fd, &event);
            }

        }
    }
}

static int execute_task(struct poll_reactor_ds* reactor, struct fdtask* task, int flags) {
    if(task == NULL) {
        return -1;
    }

    int retval = 0;
    if(flags & EPOLLIN && fd_can_read(task)) {

        task->read_task.exec(task->read_task.target);
    }

    if(flags & EPOLLOUT && fd_can_write(task)) {
        if(!(task->read_task.exec == task->write_task.exec && task->read_task.target
                == task->write_task.target && flags & EPOLLIN)) {
            task->write_task.exec(task->write_task.target);
        }
    }
    if(flags & EPOLLERR && fd_can_handle_error(task)) {
        if(!(task->read_task.exec == task->error_task.exec && task->read_task.target
                == task->error_task.target && flags & EPOLLIN) || !(task->write_task.exec
                == task->error_task.exec && task->write_task.target == task->error_task.target
                && flags & EPOLLOUT)) {
            task->error_task.exec(task->error_task.target);
        }
    }

    if(flags & EPOLLHUP) {
        //what to do here? TODO
        LOG_DBG("Received EPOLLHUP for fd: %i\n", task->fd);
    }
    return retval;
}

static int generate_epoll_ctl_flags(struct poll_reactor_ds* reactor, struct fdtask* task) {

    int flags = EPOLLET | (reactor->threaded ? EPOLLONESHOT : 0);

    if(fd_can_read(task)) {
        flags |= EPOLLIN;
    }
    if(fd_can_write(task)) {
        flags |= EPOLLOUT;
    }

    return flags;
}

static int register_interest(struct poll_reactor_ds* reactor, int fd, struct fdtask* task, int op) {
    if(reactor->state == REACTOR_STARTED) {
        /*need to interrupt the poll task*/
        //task_kill(reactor->poll_task, SIGINT);

        struct epoll_event event;
        bzero(&event, sizeof(event));

        if(task != NULL) {
            event.events = generate_epoll_ctl_flags(reactor, task);
            event.data.fd = fd;
            event.data.ptr = task;
        }

        return epoll_ctl(reactor->poll_fd, op, fd, &event);
    }

    return 0;
}

void* pr_clear_interest(struct poll_reactor_ds* reactor, int fd) {
    if(fd <= 0) {
        return NULL;
    }

    pthread_mutex_lock(&reactor->mutex);

    struct fdtask* task = g_hash_table_lookup(reactor->task_map, &fd);
    void* target = NULL;

    if(task == NULL) {
        goto out;

    }
    g_hash_table_remove(reactor->task_map, &fd);
    if(fd_can_read(task)) {
        target = task->read_task.target;
        reactor->read_count--;
    }
    if(fd_can_write(task)) {
        target = task->write_task.target;
        reactor->write_count--;
    }
    if(fd_can_handle_error(task)) {
        target = task->error_task.target;
        reactor->error_count--;
    }

    free(task);

    int retval = register_interest(reactor, fd, NULL, EPOLL_CTL_DEL);
    if(retval) {
        LOG_ERR("Could not clear interest for fd %i: %s\n", fd, strerror(errno));
    }

    out: pthread_mutex_unlock(&reactor->mutex);

    return target;
}

