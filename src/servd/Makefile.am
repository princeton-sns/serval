bin_PROGRAMS = \
	servd

if ENABLE_SERVICE_ROUTER

bin_PROGRAMS +=	servr \
		utiltest \
		trietest \
		tasktest \
		stabletest \
		messagetest

noinst_LIBRARIES = libservr.a

libservr_a_SOURCES = \
	cmwc.c \
	task.c \
	time_util.c \
	poll_reactor.c \
	prefixtrie.c \
	service_util.c \
	service_types.c \
	service_table.c \
	message_channel_base.c \
	unix_message_channel.c \
	netlink_message_channel.c \
	udp_message_channel.c \
	resolver_messaging.c \
	resolution_path.c \
	resolver_base.c

libservr_a_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src/servd \
	-I$(top_srcdir)/src/libstack \
	$(GLIB_CFLAGS)

utiltest_SOURCES = \
	util_test.c

utiltest_LDADD = \
	libservr.a

utiltest_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src/servd/ \
	-I$(top_srcdir)/src/libstack \
	$(GLIB_CFLAGS)

utiltest_LDFLAGS = \
	-L$(top_srcdir)/src/libstack \
	-L$(top_srcdir)/src/libserval \
	-L$(top_srcdir)/src/servd \
	$(GLIB_LIBS) \
	-lpthread \
	-lrt \
	-lpcl

messagetest_SOURCES = \
	messaging_test.c

messagetest_LDADD = \
	libservr.a

messagetest_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src/servd \
	-I$(top_srcdir)/src/libstack \
	$(GLIB_CFLAGS)

messagetest_LDFLAGS = \
	-L$(top_srcdir)/src/libstack \
	-L$(top_srcdir)/src/libserval \
	-L$(top_srcdir)/src/servd \
	-lserval \
	-lrt \
	-lpcl \
	$(GLIB_LIBS) \
	-lpthread 

trietest_SOURCES = \
	prefixtrie_test.c

trietest_LDADD = \
	libservr.a

trietest_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src/servd \
	-I$(top_srcdir)/src/libstack \
	$(GLIB_CFLAGS)

trietest_LDFLAGS = \
	-L$(top_srcdir)/src/libstack \
	-L$(top_srcdir)/src/libserval \
	-L$(top_srcdir)/src/servd \
	$(GLIB_LIBS) \
	-lpthread \
	-lrt \
	-lpcl

stabletest_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src/servd \
	-I$(top_srcdir)/src/libstack \
	$(GLIB_CFLAGS)

stabletest_LDFLAGS = \
	-L$(top_srcdir)/src/libstack \
	-L$(top_srcdir)/src/libserval \
	-L$(top_srcdir)/src/servd \
	$(GLIB_LIBS) \
	-lpthread \
	-lrt \
	-lpcl

stabletest_SOURCES = \
	service_table_test.c

stabletest_LDADD = \
	libservr.a

tasktest_SOURCES = \
	task_test.c

tasktest_LDADD = \
	libservr.a

tasktest_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src/servd \
	-I$(top_srcdir)/src/libstack \
	$(GLIB_CFLAGS)

tasktest_LDFLAGS = \
	-L$(top_srcdir)/src/libstack \
	-L$(top_srcdir)/src/libserval \
	-L$(top_srcdir)/src/servd \
	$(GLIB_LIBS) \
	-lpthread \
	-lrt \
	-lpcl

servr_SOURCES = \
	server_resolver.c \
	client_resolver.c \
	local_resolver.c \
	service_router.c

servr_LDADD = \
	libservr.a

servr_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src/libstack \
	$(GLIB_CFLAGS)

servr_LDFLAGS = \
	-L$(top_srcdir)/src/libstack \
	-L$(top_srcdir)/src/libserval \
	-L/usr/local/lib \
	-lstack \
	-lserval \
	-lpcl \
	-lrt \
	-lpthread \
	$(GLIB_LIBS)

endif # ENABLE_SERVICE_ROUTER

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

servd_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src/libstack

servd_LDFLAGS = \
	-L$(top_srcdir)/src/libstack \
	-L$(top_srcdir)/src/libserval \
	-lstack \
	-lserval \
	-lpthread

clean-local:
	rm -f *~
