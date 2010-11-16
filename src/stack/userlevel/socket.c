#include <scaffold/list.h>
#include <scaffold/lock.h>
#include <scaffold/debug.h>
#include <linux/net.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include "net.h"

#define SOCK_MAX (SOCK_PACKET + 1)

/* Setting NPROTO to AF_MAX is overkill here, since we effectively
 * only register Scaffold protocols. Anyhow, the net_families is just
 * an array of pointers, so the waste is not such a big deal. */
#define NPROTO AF_MAX 

static DEFINE_SPINLOCK(net_family_lock);
static const struct net_proto_family *net_families[NPROTO] = { 0 };

int sock_register(const struct net_proto_family *ops)
{
	int err = 0;
	
	if (ops->family >= AF_MAX) {
		LOG_ERR("Trying to register invalid protocol %d\n", ops->family);
		return -ENOBUFS;
	}
	
	spin_lock(&net_family_lock);
	
	if (net_families[ops->family]) {
		LOG_ERR("Family %d already registered\n", ops->family);
		err = -EEXIST;
	} else {
		net_families[ops->family] = ops;
	}
	
	spin_unlock(&net_family_lock);
	
	LOG_INF("NET: Registered protocol family %d\n", ops->family);

	return err;
}

void sock_unregister(int family)
{
	if (family < 0 || family > NPROTO) {
		LOG_ERR("NET: invalid protocol family\n");
		return;
	}

	spin_lock(&net_family_lock);
	net_families[family] = NULL;
	spin_unlock(&net_family_lock);

	LOG_INF("NET: Unregistered protocol family %d\n", family);
}

static struct socket *sock_alloc(void)
{
	struct socket *sock;

	sock = (struct socket *)malloc(sizeof(*sock));

	if (!sock)
		return NULL;
	
	memset(sock, 0, sizeof(*sock));

		
	return sock;
}

int sock_create(int family, int type, int protocol,
                struct socket **res)
{	
	int err = 0;
	struct socket *sock;
	const struct net_proto_family *pf;

	if (family < 0 || family >= NPROTO)
		return -EAFNOSUPPORT;
	if (type < 0 || type >= SOCK_MAX)
		return -EINVAL;

	spin_lock(&net_family_lock);
	
	pf = net_families[family];
	
	if (!pf) {		
		err = -EAFNOSUPPORT;
		goto out_unlock;
	}

	sock = sock_alloc();

	if (!sock) {
		/* return -ENFILE; */
		err = -ENOMEM;
		goto out_unlock;
	}

	sock->type = type;

	err = pf->create(&init_net, sock, protocol, 0);
	
	*res = sock;
out_unlock:
	spin_unlock(&net_family_lock);

	return err;
}

void sock_release(struct socket *sock)
{
	if (sock->ops) {
		sock->ops->release(sock);
		sock->ops = NULL;
	}
	free(sock);
}

