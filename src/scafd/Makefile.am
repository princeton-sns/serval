bin_PROGRAMS = scafd
scafd_SOURCES = \
	timer.c \
	scafd.c

if OS_LINUX
scafd_SOURCES += \
	rtnl.c
endif

noinst_HEADERS = \
	debug.h \
	timer.h \
	rtnl.h

scafd_CPPFLAGS =-I$(top_srcdir)/include -I$(top_srcdir)/src/libstack
scafd_LDFLAGS =-L$(top_srcdir)/src/libstack -lstack \
	-L$(top_srcdir)/src/libscaffold -lscaffold

clean-local:
	rm -f *~
