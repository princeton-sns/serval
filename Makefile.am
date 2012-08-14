ACLOCAL_AMFLAGS =-I m4

SUBDIRS = src android
dist_doc_DATA = README.md

stags:
	@cd $(top_srcdir);
	/usr/bin/etags `find . -type f -name '*.cc' -o -name '*.hh' -o -name '*.c' -o -name '*.h'`

clean-local:
	rm -f *~
	rm -f include/netinet/*~
	rm -f include/serval/*~
	rm -f include/libservalctrl/*~
	rm -f include/libserval/*~
