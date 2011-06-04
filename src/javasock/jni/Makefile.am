lib_LTLIBRARIES = libservalnet_jni.la

libservalnet_jni_la_SOURCES = \
	JNIHelp.c \
	serval_platform_ServalNetworkStack.c

#libserval_javasock_jni_includedir=$(top_srcdir)/include
#libserval_javasock_jni_include_HEADERS =

noinst_HEADERS = \
	JNIHelp.h \
	serval_platform_ServalNetworkStack.h	

libservalnet_jni_la_CPPFLAGS =-I$(top_srcdir)/include $(JAVA_INCLUDE)
libservalnet_jni_la_LDFLAGS =

EXTRA_DIST =

clean-local:
	rm -f *~
