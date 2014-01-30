if OS_LINUX

bin_PROGRAMS = translator

translator_SOURCES = \
	translator.c \
	client.c \
	worker.c

noinst_HEADERS = \
	translator.h \
	client.h \
	worker.h

translator_CPPFLAGS =-I$(top_srcdir)/include
translator_LDFLAGS =-lpthread
translator_LDADD = \
	$(top_srcdir)/src/common/libcommon.la

endif

EXTRA_DIST = \
	Android.mk \
	splice.c \
	splice.h \
	sys_splice.S \
	translator_jni.c

install-exec-hook: sysvinit
	install -m 755 $^ /etc/init.d/translator

clean-local:
	rm -f *~
