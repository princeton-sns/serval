noinst_LTLIBRARIES = libcommon.la

libcommon_la_SOURCES = \
	hashtable.c \
	heap.c \
	log.c \
	timer.c \
	signal.c

noinst_HEADERS = \
	$(top_srcdir)/include/common/platform.h \
	$(top_srcdir)/include/common/atomic.h \
	$(top_srcdir)/include/common/debug.h \
	$(top_srcdir)/include/common/hash.h \
	$(top_srcdir)/include/common/hashtable.h \
	$(top_srcdir)/include/common/heap.h \
	$(top_srcdir)/include/common/list.h \
	$(top_srcdir)/include/common/log.h \
	$(top_srcdir)/include/common/timer.h \
	$(top_srcdir)/include/common/signal.h

libcommon_la_CPPFLAGS = \
	-I$(top_srcdir)/include

libcommon_la_CFLAGS = \
	-fPIC

if OS_LINUX
libcommon_la_LIBADD = \
	-lrt
endif

EXTRA_DIST = Android.mk

clean-local:
	rm -f *~
