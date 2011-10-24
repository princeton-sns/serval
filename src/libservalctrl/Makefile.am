lib_LTLIBRARIES = libservalctrl.la

libservalctrl_la_DEPENDENCIES = \
	$(top_srcdir)/src/common/libcommon.a

libservalctrl_la_SOURCES = \
	init.c \
	task.c \
	reactor.c \
	message.c \
	message_channel.c \
	message_channel_internal.c \
	message_channel_base.c \
	message_channel_unix.c \
	message_channel_udp.c \
	hostctrl.c \
	hostctrl_local.c \
	hostctrl_remote.c

if OS_LINUX
libservalctrl_la_SOURCES += \
	reactor_epoll.c \
	message_channel_netlink.c
else
if OS_BSD
libservalctrl_la_SOURCES += \
	reactor_kqueue.c
else
libservalctrl_la_SOURCES += \
	reactor_poll.c
endif
endif

libservalctrl_la_includedir=$(includedir)/libservalctrl
libservalctrl_la_include_HEADERS = \
	$(top_srcdir)/include/libservalctrl/init.h \
	$(top_srcdir)/include/libservalctrl/reactor.h \
	$(top_srcdir)/include/libservalctrl/message.h \
	$(top_srcdir)/include/libservalctrl/message_channel.h \
	$(top_srcdir)/include/libservalctrl/task.h \
	$(top_srcdir)/include/libservalctrl/hostctrl.h

noinst_HEADERS = \
	message_channel_internal.h \
	hostctrl_ops.h

libservalctrl_la_CPPFLAGS = \
	-I$(top_srcdir)/include

libservalctrl_la_LDFLAGS = \
	-L$(top_srcdir)/src/common \
	-lcommon
	-lpthread \
	-L$(top_srcdir)/src/libserval \
	-lserval

if OS_LINUX
libservalctrl_la_LDFLAGS += \
	-lrt
endif

clean-local:
	rm -f *~

