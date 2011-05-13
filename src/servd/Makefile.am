bin_PROGRAMS = \
	servd \
	servr \
	utiltest \
	trietest \
	tasktest \
	stabletest \
	messagetest

utiltest_SOURCES = \
	util_test.c \
	time_util.c \
	service_util.c \
	service_table.c \
	prefixtrie.c \
	cmwc.c \
	service_types.c \
	task.c \
	poll_reactor.c

utiltest_CPPFLAGS =-I$(top_srcdir)/include -I$(top_srcdir)/src/servd/ -I$(top_srcdir)/src/libstack -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/opt/local/include/glib-2.0

utiltest_LDFLAGS =-L$(top_srcdir)/src/libstack \
	-L$(top_srcdir)/src/libserval \
	-L$(top_srcdir)/src/servd \
	-lglib-2.0 -lpthread -lrt -lpcl

messagetest_SOURCES = \
	messaging_test.c \
	task.c \
	cmwc.c \
	poll_reactor.c \
	service_util.c \
	service_types.c \
	message_channel_base.c \
	unix_message_channel.c \
	netlink_message_channel.c \
	udp_message_channel.c \
	resolver_messaging.c \
	resolution_path.c \
	resolver_base.c \
	time_util.c
	
	
messagetest_CPPFLAGS =-I$(top_srcdir)/include -I$(top_srcdir)/src/servd/ -I$(top_srcdir)/src/libstack -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/opt/local/include/glib-2.0

messagetest_LDFLAGS =-L$(top_srcdir)/src/libstack \
	-L$(top_srcdir)/src/libserval -lserval \
	-L$(top_srcdir)/src/servd \
	-lrt -lpcl \
	-lglib-2.0 -lpthread 
	
trietest_SOURCES = \
	service_util.c \
	time_util.c \
	cmwc.c \
	service_types.c \
	service_table.c \
	task.c \
	poll_reactor.c \
	prefixtrie.c \
	prefixtrie_test.c

trietest_CPPFLAGS =-I$(top_srcdir)/include -I$(top_srcdir)/src/servd/ -I$(top_srcdir)/src/libstack -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/opt/local/include/glib-2.0

trietest_LDFLAGS =-L$(top_srcdir)/src/libstack \
	-L$(top_srcdir)/src/libserval \
	-L$(top_srcdir)/src/servd \
	-lglib-2.0 -lpthread -lrt -lpcl

stabletest_CPPFLAGS =-I$(top_srcdir)/include -I$(top_srcdir)/src/servd/ -I$(top_srcdir)/src/libstack -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/opt/local/include/glib-2.0

stabletest_LDFLAGS =-L$(top_srcdir)/src/libstack \
	-L$(top_srcdir)/src/libserval \
	-L$(top_srcdir)/src/servd \
	-lglib-2.0 -lpthread -lrt -lpcl

stabletest_SOURCES = \
	service_util.c \
	time_util.c \
	cmwc.c \
	service_types.c \
	task.c \
	poll_reactor.c \
	prefixtrie.c \
	service_table.c \
	service_table_test.c

tasktest_SOURCES = \
	service_util.c \
	time_util.c \
	cmwc.c \
	service_types.c \
	service_table.c \
	prefixtrie.c \
	task.c \
	poll_reactor.c \
	task_test.c
	
tasktest_CPPFLAGS =-I$(top_srcdir)/include -I$(top_srcdir)/src/servd/ -I$(top_srcdir)/src/libstack -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/opt/local/include/glib-2.0 -pthread

tasktest_LDFLAGS =-L$(top_srcdir)/src/libstack \
	-L$(top_srcdir)/src/libserval \
	-L$(top_srcdir)/src/servd \
	-lglib-2.0 -lpthread -lrt -lpcl

servr_SOURCES = \
	time_util.c \
	task.c \
	cmwc.c \
	poll_reactor.c \
	prefixtrie.c \
	service_table.c \
	service_util.c \
	service_types.c \
	message_channel_base.c \
	unix_message_channel.c \
	netlink_message_channel.c \
	udp_message_channel.c \
	resolver_messaging.c \
	resolution_path.c \
	resolver_base.c \
	server_resolver.c \
	client_resolver.c \
	local_resolver.c \
	service_router.c

servr_CPPFLAGS =-I$(top_srcdir)/include -I$(top_srcdir)/src/libstack -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/opt/local/include/glib-2.0
servr_LDFLAGS =-L$(top_srcdir)/src/libstack -lstack \
	-L$(top_srcdir)/src/libserval -lserval \
	-lpcl -lrt \
	-lglib-2.0 -pthread

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


servd_CPPFLAGS =-I$(top_srcdir)/include -I$(top_srcdir)/src/libstack -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include
servd_LDFLAGS =-L$(top_srcdir)/src/libstack -lstack \
	-L$(top_srcdir)/src/libserval -lserval \
	-pthread

clean-local:
	rm -f *~
