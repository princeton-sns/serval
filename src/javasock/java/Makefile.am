# Do not install compiled class files. We instead generate and install
# a jar file with the class files in a subdirectory
noinst_JAVA = \
	serval/net/ServiceId.java \
	serval/net/ServalSocketAddress.java \
	serval/net/ServalSocket.java \
	serval/net/ServalDatagramSocket.java \
	serval/test/UDPClient.java

EXTRA_DIST=

EXTRA_DIST+= $(noinst_JAVA)

JAVAROOT=$(top_builddir)/src/javasock/java

AM_JAVACFLAGS=

clean-local:
	rm -f *~
	rm -f *.class
	rm -f *.stamp
