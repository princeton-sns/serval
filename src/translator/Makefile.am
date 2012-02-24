if OS_LINUX
bin_PROGRAMS = translator

translator_SOURCES = translator.c
translator_CPPFLAGS =-I$(top_srcdir)/include
translator_LDFLAGS =-lpthread
endif

clean-local:
	rm -f *~
