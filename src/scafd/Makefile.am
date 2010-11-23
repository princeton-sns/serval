bin_PROGRAMS = scafd
scafd_SOURCES = scafd.c

scafd_CPPFLAGS =-I$(top_srcdir)/include -I$(top_srcdir)/src/libstack
scafd_LDFLAGS =-L$(top_srcdir)/src/libstack -lstack

clean-local:
	rm -f *~
