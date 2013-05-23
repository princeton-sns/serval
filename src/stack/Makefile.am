bin_PROGRAMS = serval

serval_common_SRC = \
	debug.c \
	platform.c \
	bst.c \
	service.c \
	delay_queue.c \
	ctrl_handler.c \
	af_serval.c \
	serval_sock.c \
	serval_sal.c \
	serval_ipv4.c \
	serval_udp.c \
	serval_tcp.c \
	serval_tcp_sock.c \
	serval_tcp_input.c \
	serval_tcp_output.c \
	serval_tcp_cong.c \
	serval_tcp_metrics.c \
	serval_tcp_timer.c

serval_SOURCES = \
	$(serval_common_SRC) \
	userlevel/dst.c \
	userlevel/dev.c \
	userlevel/packet_raw.c \
	userlevel/sock.c \
	userlevel/stream.c \
	userlevel/socket.c \
	userlevel/skbuff.c \
	userlevel/checksum.c \
	userlevel/timer.c \
	userlevel/ktime.c \
	userlevel/wait.c \
	userlevel/bitops.c \
	userlevel/serval_tcp_user.c \
	userlevel/client_msg.c \
	userlevel/client.c \
	userlevel/ctrl.c \
	userlevel/telnet.c \
	userlevel/serval.c

SERVAL_INCLUDE_DIR=$(top_builddir)/include
STACK_DIR=$(top_builddir)/src/stack

SERVAL_HDR = \
	af_serval.h \
	ctrl.h \
	bst.h \
	input.h \
	service.h \
	delay_queue.h \
	serval_sock.h \
	serval_request_sock.h \
	serval_tcp_request_sock.h \
	serval_udp_sock.h \
	serval_tcp_sock.h \
	serval_ipv4.h \
	serval_sal.h \
	serval_tcp.h \
	userlevel/serval_tcp_user.h \
	$(SERVAL_INCLUDE_DIR)/serval/ctrlmsg.h \
	$(SERVAL_INCLUDE_DIR)/netinet/serval.h \
	$(SERVAL_INCLUDE_DIR)/serval/platform_tcpip.h \
	$(SERVAL_INCLUDE_DIR)/serval/platform.h \
	$(SERVAL_INCLUDE_DIR)/serval/bitops.h \
	$(SERVAL_INCLUDE_DIR)/serval/atomic.h \
	$(SERVAL_INCLUDE_DIR)/serval/list.h \
	$(SERVAL_INCLUDE_DIR)/serval/hash.h \
	$(SERVAL_INCLUDE_DIR)/serval/debug.h \
	$(SERVAL_INCLUDE_DIR)/serval/lock.h \
	$(SERVAL_INCLUDE_DIR)/serval/net.h \
	$(SERVAL_INCLUDE_DIR)/serval/dst.h \
	$(SERVAL_INCLUDE_DIR)/serval/netdevice.h \
	$(SERVAL_INCLUDE_DIR)/serval/sock.h \
	$(SERVAL_INCLUDE_DIR)/serval/inet_sock.h \
	$(SERVAL_INCLUDE_DIR)/serval/request_sock.h \
	$(SERVAL_INCLUDE_DIR)/serval/skbuff.h \
	$(SERVAL_INCLUDE_DIR)/serval/checksum.h \
	$(SERVAL_INCLUDE_DIR)/serval/ktime.h \
	$(SERVAL_INCLUDE_DIR)/serval/timer.h \
	$(SERVAL_INCLUDE_DIR)/serval/wait.h

noinst_HEADERS = \
	$(SERVAL_HDR) \
	userlevel/packet.h \
	userlevel/client_msg.h \
	userlevel/client.h \
	userlevel/serval_tcp_user.h

serval_includedir=$(includedir)/netinet
serval_include_HEADERS = \
	$(top_srcdir)/include/netinet/serval.h

serval_CPPFLAGS =-I$(SERVAL_INCLUDE_DIR) -I$(STACK_DIR)
serval_LDFLAGS =-lpthread 
serval_CFLAGS =
serval_LDADD = \
	$(top_srcdir)/src/common/libcommon.la

if OS_LINUX
serval_LDFLAGS +=-lrt
endif

# serval module
KERNEL_VER=`uname -r`
KDIR = /lib/modules/$(KERNEL_VER)/build

SERVAL_KERNEL_HDR = \
	linux/log.h

SERVAL_KERNEL_SRC = \
	$(serval_common_SRC) \
	linux/ctrl.c \
	linux/packet.c \
	linux/proc.c \
	linux/module.c \
	linux/log.c \
	linux/splice.c \
	linux/user_dma.c \
	linux/iovlock.c \
	linux/udp_encap.c \
	linux/sysctl_net_serval.c \
	linux/inet_to_serval.c

SERVAL_KERNEL_DEP = \
	$(SERVAL_INCLUDE_DIR)/serval/ctrlmsg.h \
	$(SERVAL_HDR) \
	$(SERVAL_KERNEL_HDR) \
	$(SERVAL_KERNEL_SRC)

EXTRA_DIST = \
	Android.mk \
	$(SERVAL_KERNEL_HDR) \
	$(SERVAL_KERNEL_SRC)

# This target must be left outside the ENABLE_LINUX_MODULE if-endif
# construct for Android cross-compiling to work on, e.g., Mac OS X.
serval.ko: $(SERVAL_KERNEL_DEP)
	$(MAKE) -C $(KDIR) M=$(PWD) modules

if ENABLE_LINUX_MODULE
all: serval.ko

install-data-local: serval.ko
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
endif

clean-local:
if ENABLE_LINUX_MODULE
	$(MAKE) -C $(KDIR) M=$(PWD) clean
endif
	rm -f serval.ko
	rm -f *~
	rm -f linux/*~
	rm -f userlevel/*~

