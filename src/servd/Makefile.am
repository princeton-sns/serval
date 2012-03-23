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
	-lservalctrl \
	-lserval \
	-lpthread

servd_LDADD = \
	$(top_srcdir)/src/common/libcommon.la

noinst_HEADERS = \
	$(servd_headers)

EXTRA_DIST = Android.mk

clean-local:
	rm -f *~
