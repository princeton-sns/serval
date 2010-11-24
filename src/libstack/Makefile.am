lib_LTLIBRARIES = libstack.la

libstack_la_SOURCES = \
	ctrlmsg.c \
	netlink.c \
	unix.c \
	event.c


libstack_includedir=$(includedir)/libstack
libstack_include_HEADERS = \
	$(top_srcdir)/include/libstack/stack.h \
	$(top_srcdir)/include/libstack/callback.h

noinst_HEADERS = \
	$(top_srcdir)/include/libstack/ctrlmsg.h \
	debug.h \
	init.h \
	event.h

libstack_la_CPPFLAGS =-I$(top_srcdir)/include
libstack_la_LDFLAGS =-lpthread

clean-local:
	rm -f *~

