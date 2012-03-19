if OS_LINUX

bin_PROGRAMS = translator transproxy servtransproxy

translator_SOURCES = \
	translator.c \
	log.c

transproxy_SOURCES = \
	transproxy.c \
	log.c

servtransproxy_SOURCES = \
	servtransproxy.c \
	log.c

noinst_HEADERS = \
	log.h

translator_CPPFLAGS =-I$(top_srcdir)/include
translator_LDFLAGS =-lpthread
translator_LDADD = \
	$(top_srcdir)/src/common/libcommon.la

transproxy_CPPFLAGS =-I$(top_srcdir)/include
transproxy_LDFLAGS =-lpthread

servtransproxy_CPPFLAGS =-I$(top_srcdir)/include
servtransproxy_LDFLAGS=-lpthread

endif

clean-local:
	rm -f *~
