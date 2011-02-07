bin_PROGRAMS = serval

serval_SOURCES = \
	debug.c \
	platform.c \
	bst.c \
	neighbor.c \
	service.c \
	input.c \
	output.c \
	ctrl_handler.c \
	af_serval.c \
	serval_sock.c \
	serval_srv.c \
	serval_ipv4.c \
	serval_udp.c \
	serval_tcp.c \
	userlevel/dst.c \
	userlevel/dev.c \
	userlevel/sock.c \
	userlevel/socket.c \
	userlevel/skbuff.c \
	userlevel/timer.c \
	userlevel/wait.c \
	userlevel/client_msg.c \
	userlevel/client.c \
	userlevel/ctrl.c \
	userlevel/telnet.c \
	userlevel/serval.c

if OS_LINUX
serval_SOURCES += \
	userlevel/packet_linux.c
endif

if OS_BSD
serval_SOURCES += \
	userlevel/packet_bpf.c
endif

SERVAL_INCLUDE_DIR=$(top_builddir)/include
STACK_DIR=$(top_builddir)/src/stack

SERVAL_HDR = \
	af_serval.h \
	ctrl.h \
	bst.h \
	neighbor.h \
	service.h \
	input.h \
	output.h \
	serval_sock.h \
	serval_udp_sock.h \
	serval_tcp_sock.h \
	serval_ipv4.h \
	serval_srv.h \
	$(SERVAL_INCLUDE_DIR)/libstack/ctrlmsg.h \
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
	$(SERVAL_INCLUDE_DIR)/serval/skbuff.h \
	$(SERVAL_INCLUDE_DIR)/serval/timer.h \
	$(SERVAL_INCLUDE_DIR)/serval/wait.h

noinst_HEADERS = \
	$(SERVAL_HDR) \
	userlevel/packet.h \
	userlevel/client_msg.h \
	userlevel/client.h

serval_includedir=$(includedir)/netinet
serval_include_HEADERS = \
	$(top_srcdir)/include/netinet/serval.h

serval_CPPFLAGS =-I$(SERVAL_INCLUDE_DIR) -I$(STACK_DIR)
serval_LDFLAGS =-lpthread 

if OS_LINUX
serval_LDFLAGS +=-lrt
endif

# serval module
KERNEL_VER=`uname -r`
KDIR = /lib/modules/$(KERNEL_VER)/build
TARGETS = serval.ko

SERVAL_KERNEL_HDR =

SERVAL_KERNEL_SRC = \
	linux/ctrl.c \
	linux/packet.c \
	linux/proc.c \
	linux/module.c \
	debug.c \
	platform.c \
	bst.c \
	neighbor.c \
	service.c \
	input.c \
	output.c \
	serval_sock.c \
	serval_srv.c \
	serval_ipv4.c \
	serval_udp.c \
	serval_tcp.c \
	af_serval.c

SERVAL_KERNEL_DEP = \
	$(SERVAL_INCLUDE_DIR)/libstack/ctrlmsg.h \
	$(SERVAL_HDR) \
	$(SERVAL_KERNEL_HDR) \
	$(SERVAL_KERNEL_SRC)

EXTRA_DIST = \
	Android.mk \
	$(SERVAL_KERNEL_HDR) \
	$(SERVAL_KERNEL_SRC)

if LINUX_KERNEL
all: serval.ko
endif

serval.ko: $(SERVAL_KERNEL_DEP)
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean-local:
if LINUX_KERNEL
	$(MAKE) -C $(KDIR) M=$(PWD) clean
endif
	rm -f *~
	rm -f linux/*~
	rm -f userlevel/*~

