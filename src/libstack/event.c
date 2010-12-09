/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <scaffold/list.h>
#include "event.h"
#include "debug.h"

#define MAX_HANDLERS 2

struct event_handle {
	struct event_handler *handlers[MAX_HANDLERS];
	unsigned int num_handlers;
	int pipefd[2];
	pthread_t thread;
        pthread_mutex_t mutex;
        struct list_head msgq;
};

static struct event_handle ehandle = { 
	.handlers = { NULL },
	.num_handlers = 0,
	.pipefd = { -1. -1 },
	.thread = 0,
        .mutex = PTHREAD_MUTEX_INITIALIZER
};

struct msgelm {
        struct list_head l;
        size_t datalen;
        unsigned char data[0];
};

enum { 
        SIGNAL_ERROR = -1,
        SIGNAL_UNKNOWN = 0,
        SIGNAL_EXIT,
        SIGNAL_QUEUE
};

static int eventloop_signal_read(struct event_handle *h)
{
        ssize_t sz;
	char r = 'r';

        sz = read(h->pipefd[0], &r, 1);

        if (sz == -1) {
                LOG_ERR("signal error: %s\n", strerror(errno));
                return SIGNAL_ERROR;
        }
        
        switch (r) {
        case 'x':
                return SIGNAL_EXIT;
        case 'q':
                return SIGNAL_QUEUE;
        default:
                break;
        }

	return SIGNAL_UNKNOWN;
}

static int eventloop_signal_pending(struct event_handle *h)
{
        int ret;
        struct pollfd fds;

        fds.fd = h->pipefd[0];
        fds.events = POLLIN | POLLHUP;
        fds.revents = 0;

        ret = poll(&fds, 1, 0);
        
        if (ret == -1) {
                LOG_ERR("poll error: %s\n", strerror(errno));
        }

        return ret;
}

static int eventloop_signal_queue(struct event_handle *h)
{
	char w = 'q';
        int ret;
        
        ret = eventloop_signal_pending(h);
        
        if (ret == 1)
                return 0;
        else if (ret == -1)
                return -1;

	return write(h->pipefd[1], &w, 1);
}

static int eventloop_signal_exit(struct event_handle *h)
{
	char w = 'x';
        int ret;
        
        ret = eventloop_signal_pending(h);
        
        if (ret == 1)
                return 0;
        else if (ret == -1)
                return -1;

	return write(h->pipefd[1], &w, 1);
}

static int eventloop_dequeue_msg_xmit(struct event_handle *h)
{
        int n = 0;

        while (1) {  
                struct msgelm *me;
                unsigned int i;

                pthread_mutex_lock(&h->mutex);
                
                if (list_empty(&h->msgq)) {
                        pthread_mutex_unlock(&h->mutex);
                        break;
                }
                
                me = (struct msgelm *)list_first_entry(&h->msgq, 
                                                       struct msgelm, l);
                list_del(&me->l);
                
                pthread_mutex_unlock(&h->mutex);
                
                /* Send message on all handlers */
                for (i = 0; i < h->num_handlers; i++) {
                        int ret = h->handlers[i]->send(h->handlers[i], 
                                                       me->data, me->datalen);
                        
                        if (ret == -1) {
                                LOG_ERR("send failure for handler '%s'\n",
                                        h->handlers[i]->name);
                        }
                }
                n++;
                free(me);
        }
        
        LOG_DBG("sent %d messages from queue\n", n);

        return n;
}

static int eventloop_enqueue_msg(struct event_handle *h, 
                                 const void *data, size_t datalen)
{
        struct msgelm *me;

        me = (struct msgelm *)malloc(sizeof(*me) + datalen);

        if (!me)
                return -1;

        INIT_LIST_HEAD(&me->l);
        me->datalen = datalen;        
        memcpy(me->data, data, datalen);

        pthread_mutex_lock(&h->mutex);
        list_add_tail(&me->l, &h->msgq);
        pthread_mutex_unlock(&h->mutex);
        eventloop_signal_queue(h);

        return 0;
}

int event_sendmsg(const void *data, size_t datalen)
{
        return eventloop_enqueue_msg(&ehandle, data, datalen);
}

void *eventloop_thread(void *arg)
{
	struct event_handle *h = (struct event_handle *)arg;
	int should_exit = 0;

	LOG_DBG("eventloop running - num_handlers=%u\n", h->num_handlers);

	while (!should_exit) {
		struct pollfd fds[MAX_HANDLERS + 1];
                unsigned int i;
		int ret;

		fds[0].fd = h->pipefd[0];
		fds[0].events = POLLHUP | POLLIN;
		fds[0].revents = 0;
		
		for (i = 0; i < h->num_handlers; i++) {
			fds[i+1].fd = h->handlers[i]->getfd(h->handlers[i]);
			fds[i+1].events = POLLHUP | POLLIN;
			fds[i+1].revents = 0;
		}
		
		ret = poll(fds, h->num_handlers + 1, -1);
		
		if (ret == -1) {
			LOG_ERR("poll error: %s\n", strerror(errno));
			break;
		} else if (ret == 0) {
			/* timeout, should not happen */
			continue;
		}
                
                if (fds[0].revents & POLLHUP) {
                        LOG_ERR("POLLHUP on signal pipe, other end closed?\n");
                        should_exit = 1;
                        continue;
                } else if (fds[0].revents & POLLIN) {
                        switch (eventloop_signal_read(h)) {
                        case SIGNAL_EXIT:
                                /* Thread should exit */
                                LOG_DBG("exit signal\n");
                                should_exit = 1;
                                continue;
                        case SIGNAL_QUEUE:
                                eventloop_dequeue_msg_xmit(h);
                                break;
                        case SIGNAL_ERROR:
                                LOG_ERR("Signal error!\n");
                                should_exit = 1;
                        case SIGNAL_UNKNOWN:
                        default:
                                continue;
                        }
		}
                
		for (i = 0; i < h->num_handlers; i++) {
			if (fds[i+1].revents & POLLIN) {
				/* file descriptor readable */
				ret = h->handlers[i]->handle_event(h->handlers[i]);

				if (ret == -1) {
					LOG_ERR("event handler %s failed\n",
						h->handlers[i]->name);
				}
			}
		}
	}
	LOG_DBG("event thread exits\n");

	return NULL;
}

void event_register_handler(struct event_handler *eh)
{
	if (ehandle.num_handlers == MAX_HANDLERS) {
		LOG_ERR("Max num handlers reached\n");
		return;
	}
	LOG_DBG("registering handler %s\n", eh->name);

	ehandle.handlers[ehandle.num_handlers++] = eh;
}

void event_unregister_handler(struct event_handler *eh)
{
	unsigned int i, found = 0;

	for (i = 0; i < MAX_HANDLERS; i++) {
		if (found) {
                        if (i > ehandle.num_handlers)
                                ehandle.handlers[i-1] = NULL;
                        else
                                ehandle.handlers[i-1] = ehandle.handlers[i];
		} else if (ehandle.handlers[i] == eh) {
			/* Call the handler's cleanup function */
			ehandle.handlers[i]->cleanup(ehandle.handlers[i]);
			found = 1;
                        ehandle.num_handlers--;
		}
	}
}

int eventloop_init(void)
{
	int ret = 0;
        unsigned int i = 0, num = ehandle.num_handlers;

        /* Initialize handlers */
        /* TODO: call handler cleanup if init fails. But only for
         * those handlers that have run init */
        for (i = 0; i < num; i++) {
                LOG_DBG("Initializing '%s' control\n", ehandle.handlers[i]->name);
                ret = ehandle.handlers[i]->init(ehandle.handlers[i]);
                if (ret < 0) {
                        LOG_ERR("handler '%s' init failed\n",
                                ehandle.handlers[i]->name);
                }
        }

        if (ehandle.num_handlers == 0) {
                /* No handlers successfully initialized, so
                   there is no need to run really */
                LOG_DBG("No registered control handlers\n");
                return -1;
        }

	ret = pipe(ehandle.pipefd);

	if (ret == -1) {
		LOG_ERR("pipe failed: %s\n", strerror(errno));
		return -1;
	}
	
        INIT_LIST_HEAD(&ehandle.msgq);

	ret = pthread_create(&ehandle.thread, NULL, eventloop_thread, &ehandle);

	if (ret == -1) {
		LOG_ERR("thread creation failure\n");
		close(ehandle.pipefd[0]);
		close(ehandle.pipefd[1]);
	}

	return ret;
}

void eventloop_fini(void)
{
	int ret;

	eventloop_signal_exit(&ehandle);

	LOG_DBG("joining with event loop thread\n");

	ret = pthread_join(ehandle.thread, NULL);
	
	if (ret != 0) {
		LOG_ERR("netlink thread could not join\n");
	}
        LOG_DBG("event loop thread joined\n");

	close(ehandle.pipefd[0]);
	close(ehandle.pipefd[1]);
        pthread_mutex_destroy(&ehandle.mutex);
}
