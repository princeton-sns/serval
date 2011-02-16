lib_LTLIBRARIES = libserval_javasock_jni.la

libserval_javasock_jni_la_SOURCES = \
	serval_net_ServalDatagramSocket.c

#libserval_javasock_jni_includedir=$(top_srcdir)/include
#libserval_javasock_jni_include_HEADERS =

noinst_HEADERS = \
	serval_net_ServalDatagramSocket.h	

libserval_javasock_jni_la_CPPFLAGS =-I$(top_srcdir)/include $(JAVA_INCLUDE)
libserval_javasock_jni_la_LDFLAGS =

EXTRA_DIST =

clean-local:
	rm -f *~
