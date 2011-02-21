bin_PROGRAMS = servd
servd_SOURCES = \
	timer.c \
	servd.c

if OS_LINUX
servd_SOURCES += \
	rtnl.c
endif

if OS_BSD
servd_SOURCES += \
	ifa.c
endif

noinst_HEADERS = \
	debug.h \
	timer.h \
	ifa.h \
	rtnl.h

servd_CPPFLAGS =-I$(top_srcdir)/include -I$(top_srcdir)/src/libstack
servd_LDFLAGS =-L$(top_srcdir)/src/libstack -lstack \
	-L$(top_srcdir)/src/libserval -lserval

clean-local:
	rm -f *~
