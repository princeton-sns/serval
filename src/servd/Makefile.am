bin_PROGRAMS = \
	servd

servd_SOURCES = \
	servd.c

if OS_LINUX
servd_SOURCES += \
	rtnl.c
endif

if OS_BSD
servd_SOURCES += \
	ifa.c
endif

servd_headers = \
	ifa.h \
	rtnl.h

servd_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src/libservalctrl

servd_LDFLAGS = \
	-L$(top_srcdir)/src/common \
	-L$(top_srcdir)/src/libservalctrl \
	-L$(top_srcdir)/src/libserval \
	-lcommon \
	-lservalctrl \
	-lserval \
	-lpthread

noinst_HEADERS = \
	$(servd_headers)

clean-local:
	rm -f *~
