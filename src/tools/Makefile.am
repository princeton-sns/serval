bin_PROGRAMS= \
	serv \
	servicetool \
	migrate

migrate_SOURCES = migrate.c
migrate_CPPFLAGS =-DENABLE_MAIN -I$(top_srcdir)/include 
migrate_LDFLAGS =-L$(top_srcdir)/src/libservalctrl -lservalctrl

servicetool_SOURCES = service.c
servicetool_CPPFLAGS =-DENABLE_MAIN -I$(top_srcdir)/include
servicetool_LDFLAGS =-L$(top_srcdir)/src/libservalctrl -lservalctrl

serv_SOURCES = \
	serv.c \
	migrate.c \
	service.c

serv_CPPFLAGS =-I$(top_srcdir)/include
serv_LDFLAGS =-L$(top_srcdir)/src/libservalctrl -lservalctrl

noinst_HEADERS = \
	command.h

EXTRA_DIST = Android.mk

clean-local:
	rm -f *~
