/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <stdlib.h>
#include <stdio.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include "event.h"
#include "debug.h"

#define MAX_HANDLERS 2

struct event_handle {
	struct event_handler *handlers[MAX_HANDLERS];
	unsigned int num_handlers;
	int pipefd[2];
	pthread_t thread;
};

static struct event_handle ehandle = { 
	.handlers = { NULL },
	.num_handlers = 0,
	.pipefd = { -1. -1 },
	.thread = 0
};

void *eventloop_thread(void *arg)
{
	struct event_handle *h = (struct event_handle *)arg;
	
	LOG_DBG("eventloop running - num_handlers=%u\n", h->num_handlers);

	while (1) {
		struct pollfd fds[MAX_HANDLERS + 1];
		int ret, i;

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

		if (fds[0].revents & POLLIN ||
		    fds[0].revents & POLLHUP ) {
			/* Thread should exit */
			LOG_DBG("exit signal\n");
			break;
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

static int eventloop_signal_exit(struct event_handle *h)
{
	char w = 'w';

	return write(h->pipefd[1], &w, 1);
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
	int i, found = 0;

	for (i = 0; i < ehandle.num_handlers; i++) {
		if (found) {
			ehandle.handlers[i-1] = ehandle.handlers[i];
		} else if (ehandle.handlers[i] == eh) {
			/* Call the handler's cleanup function */
			ehandle.handlers[i]->cleanup(ehandle.handlers[i]);
			found = 1;
		}
	}
	ehandle.num_handlers--;
}

int eventloop_init(void)
{
	int ret = 0;

	ret = pipe(ehandle.pipefd);

	if (ret == -1) {
		LOG_ERR("pipe failed: %s\n", strerror(errno));
		return -1;
	}
	
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
		
	close(ehandle.pipefd[0]);
	close(ehandle.pipefd[1]);
}


int libstack_init(void)
{
	return eventloop_init();
}

void libstack_fini(void) 
{
	eventloop_fini();
}
