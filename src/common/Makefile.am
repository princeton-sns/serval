lib_LIBRARIES = libcommon.a

libcommon_a_SOURCES = \
	hashtable.c \
	heap.c \
	timer.c 

noinst_HEADERS = \
	$(top_srcdir)/include/common/atomic.h \
	$(top_srcdir)/include/common/debug.h \
	$(top_srcdir)/include/common/hash.h \
	$(top_srcdir)/include/common/hashtable.h \
	$(top_srcdir)/include/common/heap.h \
	$(top_srcdir)/include/common/list.h \
	$(top_srcdir)/include/common/timer.h

libcommon_a_CPPFLAGS = \
	-I$(top_srcdir)/include

libcommon_a_CFLAGS = \
	-fPIC
