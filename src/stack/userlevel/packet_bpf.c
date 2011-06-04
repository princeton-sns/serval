/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/platform.h>
#include <serval/skbuff.h>
#include <serval/netdevice.h>
#include <sys/socket.h>
#include <serval/debug.h>
#include <serval/list.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <input.h>
#include <net/bpf.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "packet.h"

struct bpf_priv {
        char device[12];
        unsigned int buflen;
        unsigned char *buf;
};

#define get_priv(dev) ((struct bpf_priv *)dev_get_priv(dev))

/* Filter for IP packets */
static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IP, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, (u_int)-1),
        BPF_STMT(BPF_RET+BPF_K, 0),
};

#define NUM_DEVICES 4

static int packet_bpf_init(struct net_device *dev)
{
        struct bpf_priv *priv = get_priv(dev);
        struct bpf_program bpfp = 
                { sizeof(insns) / sizeof(struct bpf_insn), insns };
        unsigned int i;
        struct timeval to = { 0, 100000 };
        int ret;

        /* Try to find a free bpf device */
        for (i = 0; i < NUM_DEVICES; i++) {
                snprintf(priv->device, 12, "/dev/bpf%u", i);
                dev->fd = open(priv->device, O_RDWR);
                
                if (dev->fd == -1) {
                        LOG_ERR("bpf device open: %s\n", 
                                strerror(errno));
                } else {
                        struct ifreq ifr;
                        memset(&ifr, 0, sizeof(ifr));
                        strcpy(ifr.ifr_name, dev->name);
                        
                        ret = ioctl(dev->fd, BIOCSETIF, &ifr);
                        
                        if (ret == -1) {
                                LOG_ERR("bpf BIOCSETIF ioctl: %s\n", 
                                        strerror(errno));
                                /* Close and try the next bpf device */
                                close(dev->fd);
                        } else {
                                /* Success */
                                LOG_DBG("opened bpf device %s\n", 
                                        priv->device);
                                break;
                        }
                }
        }
        
        if (dev->fd == -1) {
                LOG_ERR("could not find a bpf device\n");
                return -1;
        }

        ret = ioctl(dev->fd, BIOCSETF, &bpfp);

        if (ret == -1) {
                LOG_ERR("bpf BIOCSETF ioctl: %s\n", 
                        strerror(errno));
                goto fail_ioctl;
        }
        
        ret = ioctl(dev->fd, BIOCGBLEN, &priv->buflen);
        
        if (ret == -1) {
                LOG_ERR("bpf BIOCGBLEN ioctl: %s\n", 
                        strerror(errno));
                goto fail_ioctl;
        }
        
        /* Capture only incoming packets (e.g., not our own outgoing
         * ones). */
        i = 0;

        ret = ioctl(dev->fd, BIOCSSEESENT, &i);
        
        if (ret == -1) {
                LOG_ERR("bpf BIOCSSEESENT ioctl: %s\n", 
                        strerror(errno));
                goto fail_ioctl;
        }
        
        i = 1;

        ret = ioctl(dev->fd, BIOCIMMEDIATE, &i);
        
        if (ret == -1) {
                LOG_ERR("bpf BIOCIMMEDIATE ioctl: %s\n", 
                        strerror(errno));
                goto fail_ioctl;
        }

        /*
        ret = ioctl(dev->fd, BIOCSRTIMEOUT, &to);
                   

        if (ret == -1) {
                LOG_ERR("bpf BIOCSRTIMEOUT ioctl: %s\n", 
                        strerror(errno));
                goto fail_ioctl;
        }   
        */
        priv->buf = (unsigned char *)malloc(priv->buflen);

        if (!priv->buf) {
                LOG_ERR("malloc failure: %s\n", 
                        strerror(errno));
                goto fail_buf;
        }

out:
        return ret;
fail_buf:
fail_ioctl:
        close(dev->fd);
        dev->fd = -1;
        ret = -1;
	goto out;
}

static void packet_bpf_destroy(struct net_device *dev)
{
        struct bpf_priv *priv = get_priv(dev);

	if (dev->fd != -1) {
		close(dev->fd);
		dev->fd = -1;
	}
        if (priv->buf)
                free(priv->buf);
}

static int packet_bpf_recv(struct net_device *dev)
{
        struct bpf_priv *priv = get_priv(dev);
        struct sk_buff *skb;
        unsigned char *ep;
        struct bpf_hdr *bh = (struct bpf_hdr *)priv->buf;
        int ret;

        /* Unfortunately, bpf mandates that we read buflen bytes data
           each time, which may include several packets. Therefore, we
           must first read into our allocated buffer and then allocate
           an skb for each individual packet followed by a copy of its
           data to the skb.
        */
        ret = read(dev->fd, priv->buf, priv->buflen);
        
        if (ret == -1) {
                LOG_ERR("read header: %s\n", 
                        strerror(errno));
                return -1;
        } else if (ret < sizeof(*bh)) {
                LOG_ERR("read too small\n");
                return -1;
        }
        
        ep = priv->buf + ret;
        
        while ((unsigned char *)bh < ep) {
                unsigned long data_len = bh->bh_caplen + 20;

                skb = alloc_skb(data_len);
                
                if (!skb) {
                        LOG_ERR("could not allocate skb\n");
                        return -1;
                }
                
                /* Copy frame */
                memcpy(skb->data, (char *)bh + bh->bh_hdrlen, 
                       bh->bh_caplen);
                
                skb_put(skb, bh->bh_caplen);
                skb->dev = dev;
                skb_reset_mac_header(skb);
                skb->pkt_type = PACKET_HOST;
                skb->protocol = htons(ETH_P_IP);
                
                ret = serval_input(skb);
                
                switch (ret) {
                case INPUT_OK:
                        break;
                case INPUT_ERROR:
                        /* Packet should be freed by upper layers */
                        if (IS_INPUT_ERROR(ret)) {
                                LOG_ERR("input error\n");
                        }
                        break;
                case INPUT_NO_PROT:
                case INPUT_DROP:
                        free_skb(skb);
                        break;
                default:
                        break;
                }
                /* Move to next packet */
                bh = (struct bpf_hdr *)((char *)bh + 
                                        BPF_WORDALIGN(bh->bh_hdrlen + 
                                                      bh->bh_caplen));
        }
        return 0;
}

static int packet_bpf_xmit(struct sk_buff *skb)
{
        int err = 0;

        err = write(skb->dev->fd, skb->data, skb->len);

        if (err == -1) {
                LOG_ERR("write error: %s\n", strerror(errno));
                err = NET_XMIT_DROP;
        } else {
                err = NET_XMIT_SUCCESS;
        }

        free_skb(skb);

        return err;
}

static struct packet_ops pack_ops = {
	.init = packet_bpf_init,
	.destroy = packet_bpf_destroy,
	.recv = packet_bpf_recv,
	.xmit = packet_bpf_xmit
};

static void dev_setup(struct net_device *dev)
{
	dev->pack_ops = &pack_ops;
	ether_setup(dev);
}

int packet_init(void)
{
        int ret;

        ret = netdev_init();

        if (ret < 0) {
                return ret;
        }

        ret = netdev_populate_table(sizeof(struct bpf_priv), dev_setup);
        
        if (ret < 0)
                netdev_fini();

        return ret;
}

void packet_fini(void)
{
        netdev_fini();
}
