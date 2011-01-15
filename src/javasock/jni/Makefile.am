lib_LTLIBRARIES = libscaffold_javasock_jni.la

libscaffold_javasock_jni_la_SOURCES = \
	edu_princeton_cs_sns_scaffold_ScaffoldDatagramSocket.c

#libscaffold_javasock_jni_includedir=$(top_srcdir)/include
#libscaffold_javasock_jni_include_HEADERS =

noinst_HEADERS = \
	edu_princeton_cs_sns_scaffold_ScaffoldDatagramSocket.h	

libscaffold_javasock_jni_la_CPPFLAGS =-I$(top_srcdir)/include $(JAVA_INCLUDE)
libscaffold_javasock_jni_la_LDFLAGS =

EXTRA_DIST =

clean-local:
	rm -f *~
