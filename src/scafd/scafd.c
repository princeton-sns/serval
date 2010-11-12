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
#include <errno.h>
#include <signal.h>

#define SF_DBG(format, ...) printf(format, ## __VA_ARGS__)

struct if_info {
	int msg_type;
	int ifindex;
	int isUp;
	int isWireless;
	char ifname[256];
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
//static int read_netlink(struct netlink_handle *nlh, struct if_info *ifinfo);

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

static int nl_parse_link_info(struct nlmsghdr *nlm, struct if_info *ifinfo)
{
	struct rtattr *rta = NULL;
	struct ifinfomsg *ifimsg = (struct ifinfomsg *) NLMSG_DATA(nlm);
	int attrlen = nlm->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
	int n = 0;

	if (!ifimsg || !ifinfo)
		return -1;

	ifinfo->isWireless = 0;
	ifinfo->ifindex = ifimsg->ifi_index;
	ifinfo->isUp = ifimsg->ifi_flags & IFF_UP ? 1 : 0;

	for (rta = IFLA_RTA(ifimsg); RTA_OK(rta, attrlen); rta = RTA_NEXT(rta, attrlen)) {
		if (rta->rta_type == IFLA_ADDRESS) {
			if (ifimsg->ifi_family == AF_UNSPEC) {
				if (RTA_PAYLOAD(rta) == ETH_ALEN) {
					memcpy(ifinfo->mac, (char *) RTA_DATA(rta), ETH_ALEN);
					n++;
				}
			}
		} else if (rta->rta_type == IFLA_IFNAME) {
			strcpy(ifinfo->ifname, (char *) RTA_DATA(rta));
			n++;
		} else if (rta->rta_type == IFLA_WIRELESS) {
			// wireless stuff
			ifinfo->isWireless = 1;
		}
	}
	return n;
}
static int nl_parse_addr_info(struct nlmsghdr *nlm, struct if_info *ifinfo)
{
	struct rtattr *rta = NULL;
	struct ifaddrmsg *ifamsg = (struct ifaddrmsg *) NLMSG_DATA(nlm);
	int attrlen = nlm->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	int n = 0;

	if (!ifamsg || !ifinfo)
		return -1;

	ifinfo->ifindex = ifamsg->ifa_index;
	for (rta = IFA_RTA(ifamsg); RTA_OK(rta, attrlen); rta = RTA_NEXT(rta, attrlen)) {
		if (rta->rta_type == IFA_ADDRESS) {
			memcpy(&ifinfo->ipaddr.sin_addr, RTA_DATA(rta), RTA_PAYLOAD(rta));
			ifinfo->ipaddr.sin_family = ifamsg->ifa_family;
		} else if (rta->rta_type == IFA_LOCAL) {
			if (RTA_PAYLOAD(rta) == ETH_ALEN) {
			}
		} else if (rta->rta_type == IFA_LABEL) {
			strcpy(ifinfo->ifname, (char *) RTA_DATA(rta));
		}
	}

	return n;
}

static int get_ipconf(struct if_info *ifinfo)
{
	struct ifreq ifr;
	struct sockaddr_in *sin = (struct sockaddr_in *) &ifr.ifr_addr;
	int sock;

	if (!ifinfo)
		return -1;
	
	sock = socket(PF_INET, SOCK_STREAM, 0);

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_ifindex = ifinfo->ifindex;
	strcpy(ifr.ifr_name, ifinfo->ifname);

	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
		close(sock);
		return -1;
	}
	memcpy(&ifinfo->ip, &sin->sin_addr, sizeof(struct in_addr));

	if (ioctl(sock, SIOCGIFBRDADDR, &ifr) < 0) {
		close(sock);
		return -1;
	}
	memcpy(&ifinfo->broadcast, &sin->sin_addr, sizeof(struct in_addr));

	close(sock);

	return 0;
}

static int read_netlink(struct netlink_handle *nlh)
{
	int len, num_msgs = 0;
	socklen_t addrlen;
	struct nlmsghdr *nlm;
	struct if_info ifinfo;
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
	for (nlm = (struct nlmsghdr *) buf; NLMSG_OK(nlm, (unsigned int) len); nlm = NLMSG_NEXT(nlm, len)) {
		struct nlmsgerr *nlmerr = NULL;
		int ret = 0;

		memset(&ifinfo, 0, sizeof(struct if_info));

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
			ret = nl_parse_link_info(nlm, &ifinfo);

			/* TODO: Should find a good way to sort out unwanted interfaces. */
			if (ifinfo.isUp) {
				
				if (get_ipconf(&ifinfo) < 0) {
					break;
				}

				if (ifinfo.mac[0] == 0 &&
                                    ifinfo.mac[1] == 0 &&
                                    ifinfo.mac[2] == 0 &&
                                    ifinfo.mac[3] == 0 &&
                                    ifinfo.mac[4] == 0 &&
                                    ifinfo.mac[5] == 0)
                                        break;
                        }
			
                        SF_DBG("Interface newlink %s %s %s\n", 
                               ifinfo.ifname, eth_to_str(ifinfo.mac), 
                               ifinfo.isUp ? "up" : "down");
			break;
		case RTM_DELLINK:
                        ret = nl_parse_link_info(nlm, &ifinfo);
		
			SF_DBG("Interface dellink %s %s\n", ifinfo.ifname, eth_to_str(ifinfo.mac));
                        break;
		case RTM_DELADDR:
			ret = nl_parse_addr_info(nlm, &ifinfo);
			SF_DBG("Interface deladdr %s %s\n", ifinfo.ifname, inet_ntoa(ifinfo.ipaddr.sin_addr));
			// Delete interface here?
		
			break;
		case RTM_NEWADDR:
			ret = nl_parse_addr_info(nlm, &ifinfo);
			SF_DBG("Interface newaddr %s %s\n", ifinfo.ifname, inet_ntoa(ifinfo.ipaddr.sin_addr));
			// Update ip address here?
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
}

int main(int argc, char **argv)
{
	struct sigaction sigact;
        struct netlink_handle nlh;
	int ret;
        fd_set readfds;

	memset(&sigact, 0, sizeof(struct sigaction));

	sigact.sa_handler = &signal_handler;
	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGHUP, &sigact, NULL);

	ret = nl_init_handle(&nlh);

	if (ret < 0) {
		SF_DBG("Could not open netlink socket\n");
                return EXIT_FAILURE;
	}

        ret = pipe(p);

        if (ret == -1) {
		SF_DBG("Could not open pipe\n");
                nl_close_handle(&nlh);
                return EXIT_FAILURE;
        }

	netlink_getlink(&nlh);

        while (!should_exit) {
                int ndfs = 0;

                FD_ZERO(&readfds);

                FD_SET(nlh.fd, &readfds);
                FD_SET(p[0], &readfds);
                
                ndfs = nlh.fd > p[0] ? nlh.fd : p[0];
                
                ret = select(nlh.fd + 1, &readfds, NULL, NULL, NULL);

                if (ret == 0) {
                        SF_DBG("Timeout...\n");
                } else if (ret == -1) {
                        SF_DBG("Error...\n");
                        should_exit = 1;
                } else {
                        if (FD_ISSET(nlh.fd, &readfds)) {
                                read_netlink(&nlh);
                        }
                        if (FD_ISSET(p[0], &readfds)) {
                                printf("Reading from pipe\n");
                                should_exit = 1;
                        }
                }        
        }

        nl_close_handle(&nlh);
        close(p[0]);
        close(p[1]);

        return EXIT_SUCCESS;
}
