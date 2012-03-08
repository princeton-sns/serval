/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _CLIENT_H_
#define _CLIENT_H_

#include <serval/list.h>
#include <pthread.h>

struct client;
struct sockaddr_un;
struct socket;

typedef enum {
	CLIENT_TYPE_UDP = 0,
	CLIENT_TYPE_TCP
} client_type_t;

typedef enum {
	CLIENT_STATE_NOT_RUNNING = 0,
	CLIENT_STATE_RUNNING,
	CLIENT_STATE_GARBAGE
} client_state_t;


enum client_signal {
        CLIENT_SIG_EXIT  = 1,
        CLIENT_SIG_READ  = 2,
        CLIENT_SIG_WRITE = 3,
};

struct client_list {
        struct list_head head;
        pthread_mutex_t mutex;        
};

#define CLIENT_LIST(list) struct client_list list = {           \
                .head = { &list.head, &list.head },             \
                .mutex = PTHREAD_MUTEX_INITIALIZER              \
        }

struct client *client_create(client_type_t type, int sock, unsigned int id, 
			     struct sockaddr_un *sa, sigset_t *sigset);
client_type_t client_get_type(struct client *c);
client_state_t client_get_state(struct client *c);
unsigned int client_get_id(struct client *c);
pthread_t client_get_thread(struct client *c);
int client_get_sockfd(struct client *c);
int client_get_signalfd(struct client *c);
const struct sockaddr *client_get_sockaddr(struct client *c);
socklen_t client_get_addrlen(struct client *c);
int client_has_data(struct client *c);
void client_hold(struct client *c);
void client_put(struct client *c);
int client_lock(struct client *c);
void client_unlock(struct client *c);
int client_signal_pending(struct client *c);
int client_signal_raise(struct client *c, enum client_signal s);
int client_signal_exit(struct client *c);
enum client_signal client_signal_lower(int fd);
int client_start(struct client *c);
struct client *client_get_by_socket(struct socket *sock, 
                                    struct client_list *list);
void client_list_init(struct client_list *list);
void client_list_add(struct client *c, struct client_list *list);
struct client *__client_list_first_entry(struct client_list *list);
struct client *__client_list_entry(struct list_head *lh);
int client_list_lock(struct client_list *list);
void client_list_unlock(struct client_list *list);
void __client_list_del(struct client *c);
void client_list_del(struct client *c, struct client_list *list);
int test_client_start(struct client *c);
int client_send_have_data_msg(struct client *c);

/**
  client_get_by_context:

  Return the client based on the current thread context.
 */
struct client *client_get_current(void);

#endif /* _CLIENT_H_ */
