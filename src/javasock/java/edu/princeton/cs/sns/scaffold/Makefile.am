# Do not install compiled class files. We instead generate and install
# a jar file with the class files in a subdirectory
noinst_JAVA = \
	ServiceId.java \
	ScaffoldSocketAddress.java \
	ScaffoldSocket.java \
	ScaffoldDatagramSocket.java

EXTRA_DIST=

EXTRA_DIST+= $(noinst_JAVA)

JAVAROOT=$(top_builddir)/src/javasock/java

AM_JAVACFLAGS=

clean-local:
	rm -f *~
	rm -f *.class
	rm -f *.stamp
