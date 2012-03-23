if OS_LINUX

bin_PROGRAMS = translator

translator_SOURCES = \
	translator.c \
	log.c

noinst_HEADERS = \
	log.h

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

clean-local:
	rm -f *~
