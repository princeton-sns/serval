/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/list.h>
#include <serval/debug.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <service.h>
#include <neighbor.h>

#define TELNET_PORT 9999
static pthread_t telnet_thread;
static int telnet_sock = -1;
static int pipefd[2] = { -1, -1 };

struct telnet_client {
	int sock;
	struct sockaddr_in inaddr;
	struct list_head lh;
};

static struct list_head telnet_client_list;

static struct telnet_client *telnet_client_create(int sock, 
						  const struct sockaddr_in *inaddr)
{
	struct telnet_client *tc;

	tc = malloc(sizeof(*tc));

	if (!tc)
		return NULL;

	memset(tc, 0, sizeof(*tc));
	
	tc->sock = sock;
	memcpy(&tc->inaddr, inaddr, sizeof(*inaddr));
	INIT_LIST_HEAD(&tc->lh);

	return tc;
}

static void telnet_client_destroy(struct telnet_client *tc)
{
	if (tc->sock != -1) 
		close(tc->sock);

	list_del(&tc->lh);
	free(tc);
}

static struct telnet_client *telnet_new_client_handle(int sock)
{
	int client_sock;
	struct sockaddr_in inaddr;
	socklen_t addrlen = 0;
	struct telnet_client *tc;

	client_sock = accept(sock, (struct sockaddr *)&inaddr, &addrlen);

	if (client_sock == -1) {
		LOG_ERR("client accept: %s\n",
			strerror(errno));
		return NULL;
	}

	tc = telnet_client_create(client_sock, &inaddr);
	
	if (!tc) {
		close(client_sock);
		return  NULL;
	}

	list_add_tail(&tc->lh, &telnet_client_list);

	return tc;
}

static void telnet_client_handle(struct telnet_client *tc)
{
	ssize_t ret;
#define BUFLEN 1024
	char buf[BUFLEN];
	char ctrlc[5] = { 0xff, 0xf4, 0xff, 0xfd, 0x06 };

	ret = recv(tc->sock, buf, BUFLEN, 0);

	if (ret == -1) {
		LOG_ERR("client recv: %s\n",
			strerror(errno));
		return;
	}

	if (ret == 0 || (ret == 5 && memcmp(buf, ctrlc, 5) == 0)) {
		telnet_client_destroy(tc);
		return;
	}
       
	/* Remove newline (we assume \n\0 at the end) */
	buf[ret-2] = '\0';

	/* LOG_DBG("request: %d %s\n", ret, buf); */
	
	if (strcmp(buf, "service_table") == 0 ||
	    strcmp(buf, "service table") == 0 ||
	    strcmp(buf, "st") == 0) {
		ret = services_print(buf, BUFLEN);

		if (ret > 0) 
			ret = send(tc->sock, buf, ret, 0);
	} else if (strcmp(buf, "neighbor_table") == 0 ||
		   strcmp(buf, "neighbor table") == 0 ||
		   strcmp(buf, "nt") == 0) {
		ret = neighbors_print(buf, BUFLEN);
		
		if (ret > 0) 
			ret = send(tc->sock, buf, ret, 0);
	} else if (strcmp(buf, "quit") == 0 ||
		   strcmp(buf, "exit") == 0) {
		telnet_client_destroy(tc);
	} else {
		ret = sprintf(buf, "syntax error.\n");
		send(tc->sock, buf, ret, 0);
	}
}

void *telnet_runloop(void *arg)
{
	struct telnet_client *tc, *tmp;

	while (1) {
		int ret, maxfd;
		fd_set readfds;

		FD_ZERO(&readfds);

		FD_SET(pipefd[0], &readfds);
		maxfd = pipefd[0];

		FD_SET(telnet_sock, &readfds);
		maxfd = telnet_sock > maxfd ? telnet_sock : maxfd;
		
		list_for_each_entry(tc, &telnet_client_list, lh) {
			FD_SET(tc->sock, &readfds);
			maxfd = tc->sock > maxfd ? tc->sock : maxfd;
		}

		ret = select(maxfd + 1, &readfds, NULL, NULL, NULL);

		if (ret == -1) {
			LOG_ERR("select: %s\n",
				strerror(errno));
		} else {
			/* Exit signal */
			if (FD_ISSET(pipefd[0], &readfds)) {
				LOG_DBG("telnet server exits\n");
				break;
			}
			/* Handle existing client */
			list_for_each_entry_safe(tc, tmp, &telnet_client_list, lh) {
				if (FD_ISSET(tc->sock, &readfds)) {
					telnet_client_handle(tc);
				}
			}
			/* New clients */
			if (FD_ISSET(telnet_sock, &readfds)) {
				telnet_new_client_handle(telnet_sock);
			}
		}
	}

	/* Cleanup clients */
	while (!list_empty(&telnet_client_list)) {
		tc = list_first_entry(&telnet_client_list, 
				      struct telnet_client, lh);
		telnet_client_destroy(tc);
	}

	return NULL;
}

int telnet_init(void)
{
	struct sockaddr_in inaddr;
	int ret;
	unsigned int on = 1;

	INIT_LIST_HEAD(&telnet_client_list);

	telnet_sock = socket(AF_INET, SOCK_STREAM, 0);
	
	if (telnet_sock == -1) {
		LOG_ERR("socket: %s\n",
			strerror(errno));
		return -1;
	}

	ret = setsockopt(telnet_sock, SOL_SOCKET, SO_REUSEADDR, 
			 &on, sizeof(on));

	if (ret == -1) {
		LOG_ERR("setsockopt: %s\n",
			strerror(errno));
		return -1;
	}

	memset(&inaddr, 0, sizeof(inaddr));
	inaddr.sin_family = AF_INET;
	inaddr.sin_port = htons(TELNET_PORT);
	inet_pton(AF_INET, "127.0.0.1", &inaddr.sin_addr);
	
	ret = bind(telnet_sock, (struct sockaddr *)&inaddr, sizeof(inaddr));
	
	if (ret == -1) {
		LOG_ERR("bind: %s\n",
			strerror(errno));
		close(telnet_sock);
		return -1;
	}
       
	ret = listen(telnet_sock, 10);

	if (ret == -1) {
		LOG_ERR("listen: %s\n",
			strerror(errno));
		close(telnet_sock);
		return -1;
	}

	if (pipe(pipefd) == -1) {
		close(telnet_sock);
		return -1;
	}

	ret = pthread_create(&telnet_thread, NULL, telnet_runloop, NULL);

	if (ret != 0) {
		close(telnet_sock);
		return -1;
	}

	return 0;
}

void telnet_fini(void)
{
	const char c = 'q';

	LOG_DBG("cleaning up server\n");

	if (pipefd[1] != -1 && write(pipefd[1], &c, 1) == -1) {
		LOG_ERR("write: %s\n",
			strerror(errno));
	}

	if (pthread_join(telnet_thread, NULL) != 0) {
		LOG_ERR("Join failed\n",
			strerror(errno));
	}
	close(telnet_sock);
}
