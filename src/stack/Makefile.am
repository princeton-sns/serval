bin_PROGRAMS = scaffold

scaffold_SOURCES = \
	debug.c \
	af_scaffold.c \
	scaffold_sock.c \
	userlevel/sock.c \
	userlevel/socket.c \
	userlevel/skbuff.c \
	userlevel/timer.c \
	userlevel/wait.c \
	userlevel/msg_ipc.c \
	userlevel/client.c \
	userlevel/packet.c \
	userlevel/scaffold.c

scaffold_DEPENDENCIES = \
	af_scaffold.h \
	scaffold_sock.h \
	userlevel/sock.h \
	userlevel/net.h \
	userlevel/skbuff.h \
	userlevel/timer.h \
	userlevel/wait.h \
	userlevel/msg_ipc.h \
	userlevel/client.h

scaffold_CPPFLAGS =-I$(top_builddir)/include -I$(top_builddir)/stack
#scaffold_CFLAGS = $(CFLAGS)
scaffold_LDFLAGS =-lpthread -lrt

#lib_LTLIBRARIES = libstack.la
#libstack_la_SOURCES = scaffold_sock.c
#libstack_la_CXXFLAGS =-I$(top_builddir)/include
#libstack_la_LDFLAGS =

noinst_HEADERS = \
	scaffold_sock.h

if KERNEL
# scaffold module
KERNEL_VER=`uname -r`
KDIR = /lib/modules/$(KERNEL_VER)/build
TARGETS = scaffold.ko

SCAFFOLD_KERNEL_DEPS = \
	linux/scaffold_netlink.c \
	linux/proc.c \
	debug.c \
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
