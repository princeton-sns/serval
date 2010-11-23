SUBDIRS = src

stags:
	@cd $(top_srcdir);
	/usr/bin/etags `find . -type f -name '*.cc' -o -name '*.hh' -o -name '*.c' -o -name '*.h'`

clean-local:
	rm -f *~
	rm -f include/netinet/*~
	rm -f include/scaffold/*~
	rm -f include/libstack/*~
	rm -f include/libscaffold/*~

EXTRA_DIST=Android.mk
