/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/list.h>
#include <serval/debug.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <service.h>
#include <serval_sock.h>

#define TELNET_ADDR "127.0.0.1"
#define TELNET_PORT 9999
static pthread_t telnet_thread;
static int telnet_sock = -1;
static int pipefd[2] = { -1, -1 };

struct telnet_client {
	int sock;
	FILE *str;
	struct sockaddr_in inaddr;
	struct list_head lh;
};

static struct list_head telnet_client_list;

struct command {
	const char *cmd_long, *cmd_short, *help_msg;
	void (*cmd_handler)(struct telnet_client *, char *, size_t);
};

static void telnet_client_destroy(struct telnet_client *tc);

static void cmd_services_print(struct telnet_client *tc, char *buf, 
                               size_t buflen)
{
	int ret;

	ret = sprintf(buf, "# Service table:\n");

	ret += service_table_print(buf + ret, buflen - ret);
		
	if (ret < 0)
		return;

	send(tc->sock, buf, ret, 0);	
}


static void cmd_flows_print(struct telnet_client *tc, char *buf, size_t buflen)
{
	int ret;
	
	ret = sprintf(buf, "# Flow table:\n");

	ret += flow_table_print(buf + ret, buflen - ret);
	
	if (ret < 0)
		return;

	send(tc->sock, buf, ret, 0);	
}

static void cmd_quit(struct telnet_client *tc, char *buf, size_t buflen)
{
	telnet_client_destroy(tc);
}

static void cmd_help(struct telnet_client *tc, char *buf, size_t buflen);

static struct command command_list[] = {
	{ "help", "h", "print help (this info)", cmd_help },
	{ "quit", "q", "quit telnet session", cmd_quit },
	{ "exit", "e", "quit telnet session", cmd_quit },
	{ "flows", "f", "print neighbor table", cmd_flows_print },
	{ "services", "s", "print service table", cmd_services_print },
	{ NULL, NULL, NULL, NULL }
};

void cmd_help(struct telnet_client *tc, char *buf, size_t buflen)
{
	int i = 0;
		
	fprintf(tc->str, "# Command list:\n");

	while (command_list[i].cmd_short) {
		fprintf(tc->str, "%s | %s\t%s\n", 
			command_list[i].cmd_long,
			command_list[i].cmd_short,
			command_list[i].help_msg);
		i++;
	}
	fflush(tc->str);
}

static struct telnet_client *telnet_client_create(int sock, 
						  const struct sockaddr_in *inaddr)
{
	struct telnet_client *tc;

	tc = malloc(sizeof(*tc));

	if (!tc)
		return NULL;

	memset(tc, 0, sizeof(*tc));
	
	tc->sock = sock;
	tc->str = fdopen(tc->sock, "w");
	memcpy(&tc->inaddr, inaddr, sizeof(*inaddr));
	INIT_LIST_HEAD(&tc->lh);

	return tc;
}

void telnet_client_destroy(struct telnet_client *tc)
{
	if (tc->sock != -1) {
		/* Closing the stream will also close the associated
		 * socket */
		fclose(tc->str);
		tc->sock = -1;
	}
	list_del(&tc->lh);
	free(tc);
	LOG_DBG("telnet client exits\n");
}

static struct telnet_client *telnet_new_client_handle(int sock)
{
	int client_sock;
	struct sockaddr_in inaddr;
	socklen_t addrlen = 0;
	struct telnet_client *tc;
#define WELCOME_MSG "# Mjau! Welcome to Serval. Type 'help' for help\n"
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

	send(tc->sock, WELCOME_MSG, strlen(WELCOME_MSG), 0);

	LOG_DBG("new telnet client\n");

	return tc;
}

static void telnet_client_handle(struct telnet_client *tc)
{
	ssize_t ret;
#define BUFLEN 9096
	char buf[BUFLEN];
	char ctrlc[5] = { 0xff, 0xf4, 0xff, 0xfd, 0x06 };
	int i = 0;

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
	while (1) {
		if (!command_list[i].cmd_short) {
			ret = sprintf(buf, "syntax error.\n");
			send(tc->sock, buf, ret, 0);
			break;
		}
		if (strcmp(buf, command_list[i].cmd_short) == 0 ||
		    strcmp(buf, command_list[i].cmd_long) == 0) {
			command_list[i].cmd_handler(tc, buf, BUFLEN);
			break;
		}
		i++;
	}
}

static void *telnet_runloop(void *arg)
{
	struct telnet_client *tc, *tmp;

	LOG_INF("TELNET SERVER - you can connect to %s:%u\n",
		TELNET_ADDR, TELNET_PORT);

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
			break;
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
	inet_pton(AF_INET, TELNET_ADDR, &inaddr.sin_addr);
	
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
