lib_LTLIBRARIES = libserval.la

COMMON_SRC = \
	accept.cc \
	bind.cc \
	close.cc \
	connect.cc \
	listen.cc \
	migrate.cc \
	message.cc \
	recv.cc \
	send.cc \
	select.cc \
	sockio.cc \
	state.cc \
	log.cc

libserval_la_SOURCES = \
	$(COMMON_SRC) \
	sf.cc \
	socket.cc \
	cli.cc

libserval_la_CXXFLAGS =-I$(top_srcdir)/include

libserval_includedir=$(includedir)/libserval
libserval_include_HEADERS = \
	$(top_srcdir)/include/libserval/serval.h

noinst_HEADERS = \
	types.h \
	cli.hh \
	socket.hh \
	message.hh \
	accept.hh \
	bind.hh \
	close.hh \
	connect.hh \
	listen.hh \
	migrate.hh \
	recv.hh \
	send.hh \
	select.hh \
	sockio.hh \
	log.hh \
	state.hh

clean-local:
	rm -f *~
