/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/platform.h>
#include <scaffold/skbuff.h>
#include <scaffold/netdevice.h>
#include <sys/socket.h>
#include <scaffold/debug.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <poll.h>
#include <input.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <fcntl.h>

/* Fake a netdevice for now */
extern const char *fixed_dev_name;

struct bpf_handle {
        int fd;
        int pipefd[2];
        int should_exit;
        char device[12];
        pthread_t thr;
        struct net_device *dev;
        unsigned int buflen;
        unsigned char *buf;
};

/* Filter for IP packets */
static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IP, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, (u_int)-1),
        BPF_STMT(BPF_RET+BPF_K, 0),
};

/* To support multiple devices, we need to make a list of these,
 * probably handle locking too for packet_xmit(). */
static struct bpf_handle *bpfh = NULL;

#define NUM_DEVICES 4

static struct bpf_handle *bpf_handle_create(const char *devname)
{
        int ret;
        unsigned int i;
        struct bpf_handle *bpfh;
        struct bpf_program bpfp = 
                { sizeof(insns) / sizeof(struct bpf_insn), insns };

        bpfh = (struct bpf_handle *)malloc(sizeof(*bpfh));

        if (!bpfh)
                return NULL;
        
        memset(bpfh, 0, sizeof(*bpfh));

        bpfh->dev = alloc_netdev(0, devname, ether_setup);

        if (!bpfh->dev) {
                LOG_ERR("Netdev alloc failure\n");
                goto fail_netdev;
        }
        
        /* Try to find a free bpf device */
        for (i = 0; i < NUM_DEVICES; i++) {
                snprintf(bpfh->device, 12, "/dev/bpf%u", i);
                bpfh->fd = open(bpfh->device, O_RDWR);
                
                if (bpfh->fd == -1) {
                        if (errno != EBUSY) {
                                LOG_ERR("packet socket: %s\n", 
                                        strerror(errno));
                                goto fail_devopen;
                        }
                } else {
                        struct ifreq ifr;
                        memset(&ifr, 0, sizeof(ifr));
                        strcpy(ifr.ifr_name, devname);
                        
                        ret = ioctl(bpfh->fd, BIOCSETIF, &ifr);
                        
                        if (ret == -1) {
                                LOG_ERR("bpf BIOCSETIF ioctl: %s\n", 
                                        strerror(errno));
                                /* Close and try the next bpf device */
                                close(bpfh->fd);
                        } else {
                                /* Success */
                                LOG_DBG("opened bpf device %s\n", 
                                        bpfh->device);
                                break;
                        }
                }
        }
        
        i = 1;

        ret = ioctl(bpfh->fd, BIOCIMMEDIATE, &i);
        
        if (ret == -1) {
                LOG_ERR("bpf BIOCIMMEDIATE ioctl: %s\n", strerror(errno));
                goto fail_ioctl;
        }
        
        LOG_DBG("bpfp.len=%d\n", bpfp.bf_len);

        ret = ioctl(bpfh->fd, BIOCSETF, &bpfp);

        if (ret == -1) {
                LOG_ERR("bpf BIOCSETF ioctl: %s\n", strerror(errno));
                goto fail_ioctl;
        }
        
        ret = ioctl(bpfh->fd, BIOCGBLEN, &bpfh->buflen);
        
        if (ret == -1) {
                LOG_ERR("bpf BIOCGBLEN ioctl: %s\n", strerror(errno));
                goto fail_ioctl;
        }
                
        bpfh->buf = (unsigned char *)malloc(bpfh->buflen);

        if (!bpfh->buf) {
                LOG_ERR("malloc failure: %s\n", strerror(errno));
                goto fail_buf;
        }


        ret = pipe(bpfh->pipefd);

        if (ret == -1) {
                LOG_ERR("could not create pipe: %s\n", strerror(errno));
                goto fail_pipe;
        }
out:
        return bpfh;
fail_pipe:
        free(bpfh->buf);
fail_buf:
fail_ioctl:
        close(bpfh->fd);
        bpfh->fd = -1;
fail_devopen:
        free_netdev(bpfh->dev);
fail_netdev:
        free(bpfh);
        bpfh = NULL;
        goto out;
}

static void bpf_handle_destroy(struct bpf_handle *bpfh)
{
        if (bpfh->pipefd[0] != -1) {
                close(bpfh->pipefd[0]);
                bpfh->pipefd[0] = -1;
        }
        if (bpfh->pipefd[1] != -1) {
                close(bpfh->pipefd[1]);
                bpfh->pipefd[1] = -1;
        }
        if (bpfh->buf)
                free(bpfh->buf);

        if (bpfh->fd) {
                close(bpfh->fd);
                bpfh->fd = -1;
        }
        if (bpfh->dev)
                free_netdev(bpfh->dev);

        free(bpfh);
        bpfh = NULL;
}

static int bpf_handle_signal(struct bpf_handle *bpfh)
{
        char w = 'w';
        return write(bpfh->pipefd[1], &w, 1);
}

int packet_xmit(struct sk_buff *skb)
{
        int err = 0;

        err = write(bpfh->fd, skb->data, skb->len);

        if (err == -1) {
                LOG_ERR("write error: %s\n", strerror(errno));
        }

        free_skb(skb);

        return err;
}

void *packet_thread(void *arg)
{
        struct bpf_handle *bpfh = (struct bpf_handle *)arg;
        int ret = 0;
        
        LOG_DBG("Packet thread running\n");

        while (!bpfh->should_exit) {
                struct pollfd fds[2];
                
                fds[0].fd = bpfh->fd;
                fds[0].events = POLLIN | POLLHUP | POLLERR;
                fds[0].revents = 0;
                fds[1].fd = bpfh->pipefd[0];
                fds[1].events = POLLIN | POLLERR;
                fds[1].revents = 0;

                ret = poll(fds, 2, -1);

                if (ret == -1) {
                        LOG_ERR("poll error: %s\n", strerror(errno));
                } else if (ret == 0) {
                        /* No timeout set, should not happen */
                } else {
                        if (fds[1].revents) {
                                bpfh->should_exit = 1;
                                LOG_DBG("Packet thread should exit\n");
                        }
                        if (fds[0].revents) {
                                struct sk_buff *skb;                
                                unsigned char *ep;
                                struct bpf_hdr *bh = (struct bpf_hdr *)bpfh->buf;
                               
                                /* Unfortunately, bpf mandates that we
                                   read buflen bytes data each time,
                                   which may include several
                                   packets. Therefore, we must first
                                   read into our allocated buffer and
                                   then allocate an skb for each
                                   individual packet followed by a
                                   copy of its data to the skb.
                                */
                                ret = read(bpfh->fd, bpfh->buf, bpfh->buflen);

                                if (ret == -1) {
                                        LOG_ERR("read header: %s\n", 
                                                strerror(errno));
                                        continue;
                                } else if (ret < sizeof(*bh)) {
                                        LOG_ERR("read too small\n");
                                        goto out_error;
                                }

                                ep = bpfh->buf + ret;

                                while ((unsigned char *)bh < ep) {
                              
                                        skb = alloc_skb(bh->bh_caplen);
                                        
                                        if (!skb) {
                                                LOG_ERR("could not allocate skb\n");
                                                goto out_error;
                                        }

                                        /* Copy frame */
                                        memcpy(skb->data, (char *)bh + bh->bh_hdrlen, 
                                               bh->bh_caplen);
                                        
                                        skb->dev = bpfh->dev;
                                        skb_reset_mac_header(skb);
                                        skb->pkt_type = PACKET_HOST;
                                        skb->protocol = htons(ETH_P_IP);
                                        
                                        ret = scaffold_input(skb);
                                        
                                        switch (ret) {
                                        case INPUT_KEEP:
                                                break;
                                        case INPUT_OK:
                                        case INPUT_ERROR:
                                        default:
                                                if (IS_INPUT_ERROR(ret)) {
                                                        LOG_ERR("input error\n");
                                                }
                                                free_skb(skb);
                                                break;
                                        }
                                        /* Move to next packet */
                                        bh = (struct bpf_hdr *)((char *)bh + 
                                                                BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen));
                                }
                        }
                }
        }
out_error:
        return NULL;
}

int packet_init(void)
{
        int ret;

        bpfh = bpf_handle_create(fixed_dev_name);

        if (!bpfh) {
                LOG_ERR("could not allocated bpf handle\n");
                return -1;
        }
        
        ret = pthread_create(&bpfh->thr, NULL, packet_thread, bpfh);

        if (ret != 0) {
                LOG_ERR("thread failure: %s\n", strerror(errno));
                bpf_handle_destroy(bpfh);
        }

        return ret;
}

void packet_fini(void)
{
        int ret;

        if (!bpfh)
                return;
        
        bpf_handle_signal(bpfh);
        
        ret = pthread_join(bpfh->thr, NULL);

        if (ret == -1) {
                LOG_ERR("Could not join\n");
        } else {
                LOG_DBG("Packet thread joined\n");
        }

        bpf_handle_destroy(bpfh);
}
