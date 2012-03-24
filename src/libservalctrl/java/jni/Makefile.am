lib_LTLIBRARIES = libservalctrl_jni.la

libservalctrl_jni_la_DEPENDENCIES = \
	$(top_srcdir)/src/libservalctrl/libservalctrl.la

libservalctrl_jni_la_SOURCES = \
	org_servalarch_servalctrl_HostCtrl.c

noinst_HEADERS = \
	org_servalarch_servalctrl_HostCtrl.h

libservalctrl_jni_la_CPPFLAGS = \
	-I$(top_srcdir)/include \
	$(JAVA_INCLUDE)

libservalctrl_jni_la_LDFLAGS = \
	-L$(top_srcdir)/src/libservalctrl \
	-lservalctrl

#libservalctrl_jni_la_LIBADD = \
#	$(top_srcdir)/src/common/libcommon.la

EXTRA_DIST = Android.mk

clean-local:
	rm -f *~
