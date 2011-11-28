/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h> 
#include <sys/select.h>
#include <sys/types.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <libserval/serval.h>
#include <libservalctrl/init.h>
#include <libservalctrl/hostctrl.h>
#include <common/list.h>
#include <errno.h>
#include <signal.h>

#define SF_DBG(format, ...) printf(format, ## __VA_ARGS__)

struct ifinfo {
	struct list_head lh;
	int msg_type;
	int ifindex;
	int isUp;
	int isWireless;
	char name[256];
	unsigned char mac[ETH_ALEN];
	struct in_addr ip;
	struct in_addr broadcast;
	struct sockaddr_in ipaddr;
};

struct netlink_handle {
        int fd;
        int seq;
        struct sockaddr_nl local;
        struct sockaddr_nl peer;
};

static struct list_head interface_list;

static char *eth_to_str(unsigned char *addr)
{
	static char buf[30];

	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		(unsigned char)addr[0], (unsigned char)addr[1],
		(unsigned char)addr[2], (unsigned char)addr[3],
		(unsigned char)addr[4], (unsigned char)addr[5]);

	return buf;
}

#define netlink_getlink(nl) netlink_request(nl, RTM_GETLINK)
#define netlink_getneigh(nl) netlink_request(nl, RTM_GETNEIGH)
#define netlink_getaddr(nl) netlink_request(nl, RTM_GETADDR | RTM_GETLINK)

static int netlink_request(struct netlink_handle *nlh, int type);

static int nl_init_handle(struct netlink_handle *nlh)
{
	int ret;
	socklen_t addrlen;

	if (!nlh)
		return -1;

	memset(nlh, 0, sizeof(struct netlink_handle));
	nlh->seq = 0;
	nlh->local.nl_family = PF_NETLINK;
	nlh->local.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR;
	nlh->local.nl_pid = getpid();
	nlh->peer.nl_family = PF_NETLINK;

	nlh->fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	if (!nlh->fd) {
		SF_DBG("Could not create netlink socket");
		return -2;
	}

	addrlen = sizeof(nlh->local);

	ret = bind(nlh->fd, (struct sockaddr *) &nlh->local, addrlen);

	if (ret == -1) {
		close(nlh->fd);
		SF_DBG("Bind for RT netlink socket failed");
		return -3;
	}
	ret = getsockname(nlh->fd, (struct sockaddr *) &nlh->local, &addrlen);

	if (ret < 0) {
		close(nlh->fd);
		SF_DBG("Getsockname failed ");
		return -4;
	}

	return 0;
}

static int nl_close_handle(struct netlink_handle *nlh)
{
	if (!nlh)
		return -1;

	return close(nlh->fd);
}

static int nl_send(struct netlink_handle *nlh, struct nlmsghdr *n)
{
	int res;
	struct iovec iov = {
		(void *) n, n->nlmsg_len
	};
	struct msghdr msg = {
		(void *) &nlh->peer, 
                sizeof(nlh->peer), 
                &iov, 1, NULL, 0, 0
	};

	n->nlmsg_seq = ++nlh->seq;
	n->nlmsg_pid = nlh->local.nl_pid;

	/* Request an acknowledgement by setting NLM_F_ACK */
	n->nlmsg_flags |= NLM_F_ACK;

	/* Send message to netlink interface. */
	res = sendmsg(nlh->fd, &msg, 0);

	if (res < 0) {
		SF_DBG("error: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int nl_parse_link_info(struct nlmsghdr *nlm, struct ifinfo *ifo)
{
	struct rtattr *rta = NULL;
	struct ifinfomsg *ifimsg = (struct ifinfomsg *) NLMSG_DATA(nlm);
	int attrlen = nlm->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
	int n = 0;

	if (!ifimsg || !ifo)
		return -1;

	ifo->isWireless = 0;
	ifo->ifindex = ifimsg->ifi_index;
	ifo->isUp = ifimsg->ifi_flags & IFF_UP ? 1 : 0;

	for (rta = IFLA_RTA(ifimsg); RTA_OK(rta, attrlen); 
	     rta = RTA_NEXT(rta, attrlen)) {
		if (rta->rta_type == IFLA_ADDRESS) {
			if (ifimsg->ifi_family == AF_UNSPEC) {
				if (RTA_PAYLOAD(rta) == ETH_ALEN) {
					memcpy(ifo->mac, (char *) 
					       RTA_DATA(rta), ETH_ALEN);
					n++;
				}
			}
		} else if (rta->rta_type == IFLA_IFNAME) {
			strcpy(ifo->name, (char *) RTA_DATA(rta));
			n++;
		} else if (rta->rta_type == IFLA_WIRELESS) {
			// wireless stuff
			ifo->isWireless = 1;
		}
	}
	return n;
}

static int nl_parse_addr_info(struct nlmsghdr *nlm, struct ifinfo *ifo)
{
	struct rtattr *rta = NULL;
	struct ifaddrmsg *ifamsg = (struct ifaddrmsg *) NLMSG_DATA(nlm);
	int attrlen = nlm->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	int n = 0;

	if (!ifamsg || !ifo)
		return -1;

	ifo->ifindex = ifamsg->ifa_index;
	for (rta = IFA_RTA(ifamsg); RTA_OK(rta, attrlen); 
	     rta = RTA_NEXT(rta, attrlen)) {
		if (rta->rta_type == IFA_ADDRESS) {
			memcpy(&ifo->ipaddr.sin_addr, 
			       RTA_DATA(rta), RTA_PAYLOAD(rta));
			ifo->ipaddr.sin_family = ifamsg->ifa_family;
		} else if (rta->rta_type == IFA_LOCAL) {
			if (RTA_PAYLOAD(rta) == ETH_ALEN) {
			}
		} else if (rta->rta_type == IFA_LABEL) {
			strcpy(ifo->name, (char *) RTA_DATA(rta));
                        n++;
		}
	}

	return n;
}

static int get_ipconf(struct ifinfo *ifo)
{
	struct ifreq ifr;
	struct sockaddr_in *sin = (struct sockaddr_in *) &ifr.ifr_addr;
	int sock;

	if (!ifo)
		return -1;
	
	sock = socket(PF_INET, SOCK_STREAM, 0);

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_ifindex = ifo->ifindex;
	strcpy(ifr.ifr_name, ifo->name);

	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
		close(sock);
		return -1;
	}
	memcpy(&ifo->ip, &sin->sin_addr, sizeof(struct in_addr));

	if (ioctl(sock, SIOCGIFBRDADDR, &ifr) < 0) {
		close(sock);
		return -1;
	}
	memcpy(&ifo->broadcast, &sin->sin_addr, sizeof(struct in_addr));

	close(sock);

	return 0;
}

static struct ifinfo *ifinfo_alloc() 
{
	struct ifinfo *ifo;

	ifo = malloc(sizeof(struct ifinfo));

	if (!ifo)
		return NULL;

	memset(ifo, 0, sizeof(struct ifinfo));
	INIT_LIST_HEAD(&ifo->lh);

	return ifo;
}

static void ifinfo_free(struct ifinfo *ifo)
{
	free(ifo);
}

static struct ifinfo *get_ifinfo(int index)
{
	struct ifinfo *ifo;

	list_for_each_entry(ifo, &interface_list, lh) {
		if (ifo->ifindex == index)
			return ifo;
	}

	return NULL;
}

static int read_netlink(struct netlink_handle *nlh, struct hostctrl *hc)
{
	int len, num_msgs = 0;
	socklen_t addrlen;
	struct nlmsghdr *nlm;
	struct ifinfo *ifo;
#define BUFLEN 2000
	char buf[BUFLEN];

	addrlen = sizeof(struct sockaddr_nl);

	memset(buf, 0, BUFLEN);

	len = recvfrom(nlh->fd, buf, BUFLEN, 0, (struct sockaddr *) &nlh->peer, &addrlen);

	if (len == EAGAIN) {
		SF_DBG("Netlink recv would block\n");
		return 0;
	}
	if (len < 0) {
		SF_DBG("len negative\n");
		return len;
	}

	for (nlm = (struct nlmsghdr *) buf; 
	     NLMSG_OK(nlm, (unsigned int) len); 
	     nlm = NLMSG_NEXT(nlm, len)) {
		struct nlmsgerr *nlmerr = NULL;
		int ret = 0;

		num_msgs++;

		switch (nlm->nlmsg_type) {
		case NLMSG_ERROR:
			nlmerr = (struct nlmsgerr *) NLMSG_DATA(nlm);
			if (nlmerr->error == 0) {
				SF_DBG("NLMSG_ACK");
			} else {
				SF_DBG("NLMSG_ERROR, error=%d type=%d\n", nlmerr->error, nlmerr->msg.nlmsg_type);
			}
			break;
		case RTM_NEWLINK:
			if (!get_ifinfo(((struct ifinfomsg *)NLMSG_DATA(nlm))->ifi_index)) {
				ifo = ifinfo_alloc();

				if (!ifo)
					break;

				ret = nl_parse_link_info(nlm, ifo);

				if (ret < 0)
				        break;

				/* TODO: Should find a good way to sort out unwanted interfaces. */
				if (ifo->isUp) {
					
					if (get_ipconf(ifo) < 0) {
						break;
					}
					
					if (ifo->mac[0] == 0 &&
					    ifo->mac[1] == 0 &&
					    ifo->mac[2] == 0 &&
					    ifo->mac[3] == 0 &&
					    ifo->mac[4] == 0 &&
					    ifo->mac[5] == 0)
						break;
				}

				if (ifo->isUp) {
					SF_DBG("Newlink: Adding interface %s %s to interface list\n", 
					       ifo->name, eth_to_str(ifo->mac));
					
					list_add(&ifo->lh, &interface_list);
				} else {
					SF_DBG("Newlink:  %s %s %s\n", 
					       ifo->name, eth_to_str(ifo->mac), 
					       ifo->isUp ? "up" : "down");
				}
			}
			break;
		case RTM_DELLINK:
			ifo = get_ifinfo(((struct ifinfomsg *)NLMSG_DATA(nlm))->ifi_index);
			
			if (ifo) {
				SF_DBG("Interface dellink %s %s\n", ifo->name, eth_to_str(ifo->mac));
				list_del(&ifo->lh);
				ifinfo_free(ifo);
			}
                        break;
		case RTM_DELADDR:
			ifo = get_ifinfo(((struct ifaddrmsg *)NLMSG_DATA(nlm))->ifa_index);
			
			if (ifo) {
				SF_DBG("Interface deladdr %s %s\n", ifo->name, inet_ntoa(ifo->ipaddr.sin_addr));

				if (!list_empty(&interface_list)) {
					struct ifinfo *ifo2 = list_first_entry(&interface_list, struct ifinfo, lh);
					SF_DBG("Migrating flows from %s to %s\n",
					       ifo->name, ifo2->name);
					hostctrl_interface_migrate(hc, ifo->name, ifo2->name);
				}
				list_del(&ifo->lh);
				ifinfo_free(ifo);
			}
			break;
		case RTM_NEWADDR:
			ifo = get_ifinfo(((struct ifaddrmsg *)NLMSG_DATA(nlm))->ifa_index);
			
			if (ifo) {
				ret = nl_parse_addr_info(nlm, ifo);
				SF_DBG("Interface newaddr %s %s\n", ifo->name, inet_ntoa(ifo->ipaddr.sin_addr));
			}
			break;
		case NLMSG_DONE:
			//SF_DBG("NLMSG_DONE\n");
			break;
		default:
			SF_DBG("Unknown netlink message\n");
			break;
		}
	}
	return num_msgs;
}

static int netlink_request(struct netlink_handle *nlh, int type)
{
	struct {
		struct nlmsghdr nh;
		struct rtgenmsg rtg;
	} req;

	if (!nlh)
		return -1;

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req));
	req.nh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.nh.nlmsg_type = type;
	req.rtg.rtgen_family = AF_INET;

	// Request interface information
	return nl_send(nlh, &req.nh);
}

static int should_exit = 0;
static int p[2] = { -1, -1 };

static void signal_handler(int sig)
{
        ssize_t ret;
        char q = 'q';

        printf("Writing to pipe\n");

        ret = write(p[1], &q, 1);

	if (ret < 0) {
                fprintf(stderr, "Could not write to pipe: %s\n", 
                        strerror(errno));
	}
}

int main(int argc, char **argv)
{
	struct sigaction sigact;
        struct netlink_handle nlh;
	int ret;
        fd_set readfds;
        struct hostctrl *hc;

	memset(&sigact, 0, sizeof(struct sigaction));

	INIT_LIST_HEAD(&interface_list);

	sigact.sa_handler = &signal_handler;
	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGHUP, &sigact, NULL);

	ret = nl_init_handle(&nlh);

	if (ret < 0) {
		SF_DBG("Could not open netlink socket\n");
		goto fail_netlink;
	}

        ret = pipe(p);

        if (ret == -1) {
		SF_DBG("Could not open pipe\n");
		goto fail_pipe;
        }

	ret = libservalctrl_init();

	if (ret == -1) {
		SF_DBG("Could not init libservalctrl\n");
		goto fail_ctrl;
	}
        
        hc = hostctrl_local_create(NULL, NULL, HCF_START);
	
        if (!hc) {
                ret = -1;
		SF_DBG("Could not create host control handle\n");
                goto fail_hostctrl;
        }

	netlink_getlink(&nlh);

        while (!should_exit) {
                int ndfs = 0;

                FD_ZERO(&readfds);

                FD_SET(nlh.fd, &readfds);
                FD_SET(p[0], &readfds);
                
                ndfs = nlh.fd > p[0] ? nlh.fd : p[0];
                
                ret = select(ndfs + 1, &readfds, NULL, NULL, NULL);

                if (ret == 0) {
                        SF_DBG("Timeout...\n");
                } else if (ret == -1) {
                        SF_DBG("Error...\n");
                        should_exit = 1;
                } else {
                        if (FD_ISSET(nlh.fd, &readfds)) {
                                read_netlink(&nlh, hc);
                        }
                        if (FD_ISSET(p[0], &readfds)) {
                                printf("Reading from pipe\n");
                                should_exit = 1;
                        }
                }        
        }

	hostctrl_free(hc);
fail_hostctrl:
	libservalctrl_fini();
fail_ctrl:
        close(p[0]);
        close(p[1]);
fail_pipe:
        nl_close_handle(&nlh);
fail_netlink:

	while (!list_empty(&interface_list)) {
		struct ifinfo *ifo;
		ifo = list_first_entry(&interface_list, struct ifinfo, lh);
		list_del(&ifo->lh);
		ifinfo_free(ifo);
	}

        return ret;
}
