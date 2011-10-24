if ENABLE_SERVICE_ROUTER
bin_PROGRAMS = servr
	utiltest \
	trietest \
	stabletest

noinst_LIBRARIES = libservr.a

libservr_a_SOURCES = \
	cmwc.c \
	time_util.c \
	service_util.c \
	service_types.c \
	prefixtrie.c \
	service_table.c \
	resolver_base.c \
	resolver_messaging.c

libservr_headers = \
	cmwc.h \
	time_util.h \
	service_types.h \
	service_util.h \
	prefixtrie.h \
	service_table.h \
	resolver_base.h \
	resolver.h \
	resolver_messaging.h

libservr_a_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src/servd \
	-I$(top_srcdir)/src/libservalctrl \
	$(GLIB_CFLAGS)

utiltest_SOURCES = \
	util_test.c

utiltest_LDADD = \
	libservr.a

utiltest_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src/servd/ \
	-I$(top_srcdir)/src/libservalctrl \
	$(GLIB_CFLAGS)

utiltest_LDFLAGS = \
	-L$(top_srcdir)/src/libservalctrl \
	-L$(top_srcdir)/src/libserval \
	-L$(top_srcdir)/src/servd \
	$(GLIB_LIBS) \
	-lpthread \
	-lrt

#messagetest_SOURCES = \
#	messaging_test.c

#messagetest_LDADD = \
#	libservr.a

#messagetest_CPPFLAGS = \
#	-I$(top_srcdir)/include \
#	-I$(top_srcdir)/src/servd \
#	-I$(top_srcdir)/src/libservalctrl \
#	$(GLIB_CFLAGS)

#messagetest_LDFLAGS = \
#	-L$(top_srcdir)/src/libservalctrl \
#	-L$(top_srcdir)/src/libserval \
#	-L$(top_srcdir)/src/servd \
#	-lserval \
#	-lrt \
#	$(GLIB_LIBS) \
#	-lpthread 

trietest_SOURCES = \
	prefixtrie_test.c

trietest_LDADD = \
	libservr.a

trietest_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src/servd \
	-I$(top_srcdir)/src/libservalctrl \
	$(GLIB_CFLAGS)

trietest_LDFLAGS = \
	-L$(top_srcdir)/src/libservalctrl \
	-L$(top_srcdir)/src/libserval \
	-L$(top_srcdir)/src/servd \
	$(GLIB_LIBS) \
	-lpthread \
	-lrt

stabletest_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src/servd \
	-I$(top_srcdir)/src/libservalctrl \
	$(GLIB_CFLAGS)

stabletest_LDFLAGS = \
	-L$(top_srcdir)/src/libservalctrl \
	-L$(top_srcdir)/src/libserval \
	-L$(top_srcdir)/src/servd \
	$(GLIB_LIBS) \
	-lpthread \
	-lrt

stabletest_SOURCES = \
	service_table_test.c

stabletest_LDADD = \
	libservr.a

#tasktest_SOURCES = \
#	task_test.c

#tasktest_LDADD = \
#	libservr.a

#tasktest_CPPFLAGS = \
#	-I$(top_srcdir)/include \
#	-I$(top_srcdir)/src/servd \
#	-I$(top_srcdir)/src/libservalctrl \
#	$(GLIB_CFLAGS)

#tasktest_LDFLAGS = \
#	-L$(top_srcdir)/src/libservalctrl \
#	-L$(top_srcdir)/src/libserval \
#	-L$(top_srcdir)/src/servd \
#	$(GLIB_LIBS) \
#	-lpthread \
#	-lrt

servr_SOURCES = \
	server_resolver.c \
	client_resolver.c \
	local_resolver.c \
	service_router.c

servr_headers = \
	server_resolver.h

servr_LDADD = \
	libservr.a

servr_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src/libservalctrl \
	$(GLIB_CFLAGS)

servr_LDFLAGS = \
	-L$(top_srcdir)/src/libservalctrl \
	-L$(top_srcdir)/src/libserval \
	-lserval \
	-lservalctrl \
	-lrt \
	-lpthread \
	$(GLIB_LIBS)

noinst_HEADERS = \
	$(servr_headers)

indent:
	indent -kr -i4 -lc80 \
	$(libservr_a_SOURCES) \
	$(servr_SOURCES) \
	$(libservr_headers) \
	$(servr_headers)

endif # ENABLE_SERVICE_ROUTER

clean-local:
	rm -f *~

