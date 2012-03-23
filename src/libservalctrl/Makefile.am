SUBDIRS = .

if ENABLE_JAVA_BINDINGS
SUBDIRS += java
endif

lib_LTLIBRARIES = libservalctrl.la

libservalctrl_la_DEPENDENCIES = \
	$(top_srcdir)/src/common/libcommon.la

libservalctrl_la_SOURCES = \
	init.c \
	message.c \
	message_channel.c \
	message_channel_internal.c \
	message_channel_base.c \
	message_channel_udp.c \
	hostctrl.c \
	hostctrl_local.c \
	hostctrl_remote.c

if OS_UNIX
libservalctrl_la_SOURCES += \
	message_channel_unix.c
endif

if OS_LINUX
libservalctrl_la_SOURCES += \
	message_channel_netlink.c
endif

libservalctrl_la_includedir=$(includedir)/libservalctrl
libservalctrl_la_include_HEADERS = \
	$(top_srcdir)/include/libservalctrl/init.h \
	$(top_srcdir)/include/libservalctrl/message.h \
	$(top_srcdir)/include/libservalctrl/message_channel.h \
	$(top_srcdir)/include/libservalctrl/hostctrl.h

noinst_HEADERS = \
	message_channel_base.h \
	message_channel_internal.h \
	hostctrl_ops.h

libservalctrl_la_CPPFLAGS = \
	-I$(top_srcdir)/include

libservalctrl_la_LDFLAGS = \
	-L$(top_srcdir)/src/common \
	-lpthread

libservalctrl_la_LIBADD = \
	$(top_srcdir)/src/common/libcommon.la

if ENABLE_USERMODE
libservalctrl_la_CPPFLAGS += \
	-DENABLE_USERMODE

libservalctrl_la_LDFLAGS += \
	-L$(top_srcdir)/src/libserval \
	-lserval
endif

EXTRA_DIST = Android.mk

clean-local:
	rm -f *~

