bin_PROGRAMS = scaffold

scaffold_SOURCES = \
	debug.c \
	af_scaffold.c \
	scaffold_sock.c \
	input.c \
	userlevel/sock.c \
	userlevel/socket.c \
	userlevel/skbuff.c \
	userlevel/timer.c \
	userlevel/wait.c \
	userlevel/msg_ipc.c \
	userlevel/client.c \
	userlevel/packet.c \
	userlevel/scaffold.c

SCAFFOLD_INCLUDE_DIR=$(top_builddir)/include
STACK_DIR=$(top_builddir)/src/stack

noinst_HEADERS = \
	af_scaffold.h \
	scaffold_sock.h \
	input.h \
	userlevel/msg_ipc.h \
	userlevel/client.h \
	$(SCAFFOLD_INCLUDE_DIR)/netinet/scaffold.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/platform.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/atomic.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/list.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/hash.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/debug.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/lock.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/net.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/skbuff.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/timer.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/wait.h

#scaffold_CFLAGS = $(CFLAGS)
scaffold_CPPFLAGS =-I$(SCAFFOLD_INCLUDE_DIR) -I$(STACK_DIR)
scaffold_LDFLAGS =-lpthread -lrt

#lib_LTLIBRARIES = libstack.la
#libstack_la_SOURCES = scaffold_sock.c
#libstack_la_CXXFLAGS =-I$(top_builddir)/include
#libstack_la_LDFLAGS =

if KERNEL
# scaffold module
KERNEL_VER=`uname -r`
KDIR = /lib/modules/$(KERNEL_VER)/build
TARGETS = scaffold.ko

SCAFFOLD_KERNEL_DEPS = \
	$(SCAFFOLD_INCLUDE_DIR)/netinet/scaffold.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/platform.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/debug.h \
	$(SCAFFOLD_INCLUDE_DIR)/scaffold/lock.h \
	$(STACK_DIR)/linux/scaffold_netlink.c \
	$(STACK_DIR)/linux/proc.c \
	debug.c \
	input.c \
	af_scaffold.c \
	scaffold_sock.c

all: scaffold.ko

scaffold.ko: $(SCAFFOLD_KERNEL_DEPS)
	$(MAKE) -C /lib/modules/$(KERNEL_VER)/build M=$(PWD) modules

clean-local:
	$(MAKE) -C /lib/modules/$(KERNEL_VER)/build M=$(PWD) clean
	rm -f *~
	rm -f linux/*~
	rm -f userlevel/*~
endif # KERNEL
