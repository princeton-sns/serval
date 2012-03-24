/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- 
 *
 * Pipe-based IPC signals for waking/signaling between threads.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <common/signal.h>

int signal_init(struct signal *s)
{
    int ret;

    if (!s)
        return -1;

    ret = pipe(s->fd);

    if (ret == -1)
        return ret;

    ret = fcntl(s->fd[0], F_SETFL, O_NONBLOCK);
    
    if (ret == -1) {
        close(s->fd[0]);
        close(s->fd[1]);
    } else 
        ret = 0;

    atomic_set(&s->waiting, 0);
    
    return ret;
}

void signal_destroy(struct signal *s)
{
    close(s->fd[0]);
    close(s->fd[1]);
}

int signal_clear_val(struct signal *s, int *val)
{
    int ret = 1;
    
    while (ret > 0) {        
        ret = read(s->fd[0], val, sizeof(*val));

        if (ret == -1) {
            if (errno == EWOULDBLOCK)
                ret = 0;
        }
    }

    return ret > 0 ? 1 : ret;
}

int signal_clear(struct signal *s)
{
    int val;
    
    return signal_clear_val(s, &val);
}

int signal_get_fd(struct signal *s)
{
    return s->fd[0];
}

int signal_wait_val(struct signal *s, int timeout, int *val)
{
    int sig = 0, ret = 0;
    ssize_t n = 0;

    atomic_inc(&s->waiting);

    if (!val)
        val = &sig;
    
    do {
        n = read(s->fd[0], val, sizeof(*val));

        if (n == -1) {
            if (errno == EWOULDBLOCK) {
                struct pollfd fds;
                
                memset(&fds, 0, sizeof(fds));
                fds.fd = s->fd[0];
                fds.events = POLLIN | POLLHUP | POLLERR;
                
                ret = poll(&fds, 1, timeout);
                
                if (ret <= 0)
                    break;

                n = 0;
            }
        } else
            ret = n > 0 ? 1 : 0;
    } while (n == 0); 

    signal_clear(s);
    
    atomic_dec(&s->waiting);

    return ret;
}

int signal_wait(struct signal *s, int timeout)
{
    return signal_wait_val(s, timeout, NULL);
}

int signal_raise_val(struct signal *s, int val)
{
    if (signal_is_raised(s))
        return 0;
    
    return write(s->fd[1], &val, sizeof(val));
}

int signal_raise(struct signal *s)
{
    return signal_raise_val(s, 0);
}

int signal_is_raised(const struct signal *s)
{
        struct pollfd fds;
        
        memset(&fds, 0, sizeof(fds));
        fds.fd = s->fd[0];
        fds.events = POLLIN;
        
        if (poll(&fds, 1, 0) > 0)
            return 1;
                
        return 0;
}

unsigned int signal_num_waiting(struct signal *s)
{
    return atomic_read(&s->waiting);
}
