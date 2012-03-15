# Do not install compiled class files. We instead generate and install
# a jar file with the class files in a subdirectory
noinst_JAVA = \
	org/servalarch/net/ServiceID.java \
	org/servalarch/net/ServalSocketAddress.java \
	org/servalarch/platform/ServalNetworkStack.java \
	org/servalarch/net/ServalDatagramPacket.java \
	org/servalarch/net/ServalDatagramSocket.java \
	org/servalarch/net/ServalDatagramSocketImpl.java \
	org/servalarch/net/ServalDatagramSocketImplFactory.java \
	org/servalarch/net/ServalServerDatagramSocket.java \
	org/servalarch/net/ServalSocketImplFactory.java \
	org/servalarch/net/ServalSocketOutputStream.java \
	org/servalarch/net/ServalSocketImpl.java \
	org/servalarch/net/ServalPlainSocketImpl.java \
	org/servalarch/net/ServalSocketInputStream.java \
	org/servalarch/net/ServalSocket.java \
	org/servalarch/net/ServalServerSocket.java \
	org/servalarch/net/ServalPlainServerSocketImpl.java \
	org/servalarch/test/TCPServer.java \
	org/servalarch/test/TCPClient.java \
	org/servalarch/test/UDPServer.java \
	org/servalarch/test/UDPClient.java

EXTRA_DIST=

EXTRA_DIST+= $(noinst_JAVA)

JAVAROOT=$(top_builddir)/src/javasock/java

AM_JAVACFLAGS=

clean-local:
	rm -f org/servalarch/test/*~
	rm -f org/servalarch/net/*~
	rm -f org/servalarch/platform/*~
	rm -f *~
	rm -f *.class
	rm -f *.stamp
