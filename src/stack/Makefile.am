bin_PROGRAMS = scaffold

scaffold_SOURCES = \
	scaffold_sock.c \
	userlevel/sock.c \
	userlevel/skbuff.c \
	userlevel/timer.c \
	userlevel/scaffold.c

scaffold_DEPENDENCIES = \
	scaffold_sock.h \
	userlevel/sock.h \
	userlevel/net.h \
	userlevel/skbuff.h \
	userlevel/timer.h

scaffold_CPPFLAGS =-I$(top_builddir)/include -I$(top_builddir)/stack
#scaffold_CFLAGS = $(CFLAGS)
scaffold_LDFLAGS =-lpthread -lrt

#lib_LTLIBRARIES = libstack.la
#libstack_la_SOURCES = scaffold_sock.c
#libstack_la_CXXFLAGS =-I$(top_builddir)/include
#libstack_la_LDFLAGS =

noinst_HEADERS = \
	scaffold_sock.h

# scaffold module
KERNEL_VER=`uname -r`
KDIR = /lib/modules/$(KERNEL_VER)/build
TARGETS = scaffold.ko

SCAFFOLD_KERNEL_DEPS = \
	linux/af_scaffold.c \
	linux/scaffold_netlink.c \
	linux/proc.c \
	scaffold_sock.c

all: scaffold.ko

scaffold.ko: $(SCAFFOLD_KERNEL_DEPS)
	$(MAKE) -C /lib/modules/$(KERNEL_VER)/build M=$(PWD) modules

clean-local:
	$(MAKE) -C /lib/modules/$(KERNEL_VER)/build M=$(PWD) clean
	rm -f *~
	rm -f linux/*~
	rm -f userlevel/*~
