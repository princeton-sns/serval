#ifndef _CLIENT_H_
#define _CLIENT_H_

#include <scaffold/list.h>
#include <pthread.h>

struct client;
struct sockaddr_un;

typedef enum {
	CLIENT_TYPE_UDP = 0,
	CLIENT_TYPE_TCP
} client_type_t;

typedef enum {
	CLIENT_STATE_NOT_RUNNING = 0,
	CLIENT_STATE_RUNNING,
	CLIENT_STATE_GARBAGE
} client_state_t;

struct client *client_create(client_type_t type, int sock, unsigned int id, 
			     struct sockaddr_un *sa, sigset_t *sigset);
client_type_t client_get_type(struct client *c);
client_state_t client_get_state(struct client *c);
unsigned int client_get_id(struct client *c);
pthread_t client_get_thread(struct client *c);
void client_destroy(struct client *c);
int client_signal_pending(struct client *c);
int client_signal_raise(struct client *c);
int client_signal_exit(struct client *c);
int client_signal_lower(struct client *c);
int client_start(struct client *c);
void client_list_add(struct client *c, struct list_head *head);
struct client *client_list_first_entry(struct list_head *head);
struct client *client_list_entry(struct list_head *lh);
void client_list_del(struct client *c);
int test_client_start(struct client *c);

/**
  client_get_by_context:

  Return the client based on the current thread context.
 */
struct client *client_get_current(void);

#endif /* _CLIENT_H_ */
