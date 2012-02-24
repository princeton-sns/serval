bin_PROGRAMS= \
	servicetool \
	migrate

migrate_SOURCES = migrate.c
migrate_CPPFLAGS = -I$(top_srcdir)/include 
migrate_LDFLAGS =-L$(top_srcdir)/src/libservalctrl -lservalctrl

servicetool_SOURCES = servicetool.c
servicetool_CPPFLAGS =-I$(top_srcdir)/include
servicetool_LDFLAGS =-L$(top_srcdir)/src/libservalctrl -lservalctrl

clean-local:
	rm -f *~
