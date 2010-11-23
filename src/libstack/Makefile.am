lib_LTLIBRARIES = libstack.la

libstack_la_SOURCES = \
	netlink.c \
	event.c

#libstack_include_HEADERS =
noinst_HEADERS = \
	debug.h \
	event.h

libstack_la_CPPFLAGS =-I$(top_srcdir)/include
libstack_la_LDFLAGS =-lpthread

clean-local:
	rm -f *~

