if OS_LINUX

bin_PROGRAMS = translator transproxy

translator_SOURCES = \
	translator.c \
	log.c

transproxy_SOURCES = \
	transproxy.c \
	log.c

noinst_HEADERS = \
	log.h

translator_CPPFLAGS =-I$(top_srcdir)/include
translator_LDFLAGS =-lpthread

transproxy_CPPFLAGS =-I$(top_srcdir)/include
transproxy_LDFLAGS =-lpthread

endif

clean-local:
	rm -f *~
