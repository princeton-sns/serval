bin_PROGRAMS = scaffold

scaffold_SOURCES = \
	debug.c \
	platform.c \
	bst.c \
	service.c \
	input.c \
	output.c \
	ctrl_handler.c \
	af_scaffold.c \
	scaffold_sock.c \
	scaffold_srv.c \
	scaffold_ipv4.c \
	scaffold_udp.c \
	scaffold_tcp.c \
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
	userlevel/scaffold.c

if OS_LINUX
scaffold_SOURCES += \
	userlevel/packet_linux.c
endif

if OS_BSD
scaffold_SOURCES += \
	userlevel/packet_bpf.c
endif

SCAFFOLD_INCLUDE_DIR=$(top_builddir)/include
STACK_DIR=$(top_builddir)/src/stack

SCAFFOLD_HDR = \
	af_scaffold.h \
	ctrl.h \
	bst.h \
	service.h \
	input.h \
	output.h \
	scaffold_sock.h \
	scaffold_udp_sock.h \
	scaffold_tcp_sock.h \
	scaffold_ipv4.h \
	scaffold_srv.h \
	$(SCAFFOLD_INCLUDE_DIR)/libstack/ctrlmsg.h \
	$(SCAFFOLD_INCLUDE_DIR)/netinet/scaffold.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/platform_tcpip.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/platform.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/atomic.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/list.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/hash.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/debug.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/lock.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/net.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/dst.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/netdevice.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/sock.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/skbuff.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/timer.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/wait.h

noinst_HEADERS = \
	$(SCAFFOLD_HDR) \
	userlevel/packet.h \
	userlevel/client_msg.h \
	userlevel/client.h

scaffold_includedir=$(includedir)/netinet
scaffold_include_HEADERS = \
	$(top_srcdir)/include/netinet/scaffold.h

scaffold_CPPFLAGS =-I$(SCAFFOLD_INCLUDE_DIR) -I$(STACK_DIR)
scaffold_LDFLAGS =-lpthread 

if OS_LINUX
scaffold_LDFLAGS +=-lrt
endif

# scaffold module
KERNEL_VER=`uname -r`
KDIR = /lib/modules/$(KERNEL_VER)/build
TARGETS = scaffold.ko

SCAFFOLD_KERNEL_HDR =

SCAFFOLD_KERNEL_SRC = \
	linux/ctrl.c \
	linux/packet.c \
	linux/proc.c \
	linux/module.c \
	debug.c \
	platform.c \
	bst.c \
	service.c \
	input.c \
	output.c \
	scaffold_sock.c \
	scaffold_srv.c \
	scaffold_ipv4.c \
	scaffold_udp.c \
	scaffold_tcp.c \
	af_scaffold.c

SCAFFOLD_KERNEL_DEP = \
	$(SCAFFOLD_INCLUDE_DIR)/libstack/ctrlmsg.h \
	$(SCAFFOLD_HDR) \
	$(SCAFFOLD_KERNEL_HDR) \
	$(SCAFFOLD_KERNEL_SRC)

EXTRA_DIST = \
	Android.mk \
	$(SCAFFOLD_KERNEL_HDR) \
	$(SCAFFOLD_KERNEL_SRC)

if LINUX_KERNEL
all: scaffold.ko
endif

scaffold.ko: $(SCAFFOLD_KERNEL_DEP)
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean-local:
if LINUX_KERNEL
	$(MAKE) -C $(KDIR) M=$(PWD) clean
endif
	rm -f *~
	rm -f linux/*~
	rm -f userlevel/*~

