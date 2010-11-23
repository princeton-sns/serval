bin_PROGRAMS = scaffold

scaffold_SOURCES = \
	debug.c \
	platform.c \
	input.c \
	output.c \
	af_scaffold.c \
	scaffold_sock.c \
	scaffold_ipv4.c \
	scaffold_udp.c \
	scaffold_tcp.c \
	userlevel/dev.c \
	userlevel/sock.c \
	userlevel/socket.c \
	userlevel/skbuff.c \
	userlevel/timer.c \
	userlevel/wait.c \
	userlevel/client_msg.c \
	userlevel/client.c \
	userlevel/packet.c \
	userlevel/ctrl.c \
	userlevel/scaffold.c

SCAFFOLD_INCLUDE_DIR=$(top_builddir)/include
STACK_DIR=$(top_builddir)/src/stack

SCAFFOLD_HDR = \
	af_scaffold.h \
	ctrl.h \
	input.h \
	output.h \
	scaffold_sock.h \
	scaffold_udp_sock.h \
	scaffold_tcp_sock.h \
	scaffold_ipv4.h \
	$(SCAFFOLD_INCLUDE_DIR)/libstack/ctrlmsg.h \
	$(SCAFFOLD_INCLUDE_DIR)/netinet/scaffold.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/platform.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/atomic.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/list.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/hash.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/debug.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/lock.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/net.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/netdevice.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/sock.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/skbuff.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/timer.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/wait.h

noinst_HEADERS = \
	$(SCAFFOLD_HDR) \
	userlevel/client_msg.h \
	userlevel/client.h

scaffold_CPPFLAGS =-I$(SCAFFOLD_INCLUDE_DIR) -I$(STACK_DIR)
scaffold_LDFLAGS =-lpthread -lrt

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
	input.c \
	output.c \
	scaffold_ipv4.c \
	scaffold_sock.c \
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

scaffold.ko: $(SCAFFOLD_KERNEL_DEP)
	$(MAKE) -C /lib/modules/$(KERNEL_VER)/build M=$(PWD) modules

clean-local:
	$(MAKE) -C /lib/modules/$(KERNEL_VER)/build M=$(PWD) clean
	rm -f *~
	rm -f linux/*~
	rm -f userlevel/*~
endif # KERNEL

