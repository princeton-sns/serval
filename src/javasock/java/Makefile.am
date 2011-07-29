# Do not install compiled class files. We instead generate and install
# a jar file with the class files in a subdirectory
noinst_JAVA = \
	serval/net/ServiceID.java \
	serval/net/ServalSocketAddress.java \
	serval/platform/ServalNetworkStack.java \
	serval/net/ServalDatagramPacket.java \
	serval/net/ServalDatagramSocket.java \
	serval/net/ServalDatagramSocketImpl.java \
	serval/net/ServalDatagramSocketImplFactory.java \
	serval/net/ServalServerDatagramSocket.java \
	serval/net/ServalSocketImplFactory.java \
	serval/net/ServalSocketOutputStream.java \
	serval/net/ServalSocketImpl.java \
	serval/net/ServalPlainSocketImpl.java \
	serval/net/ServalSocketInputStream.java \
	serval/net/ServalSocket.java \
	serval/net/ServalServerSocket.java \
	serval/net/ServalPlainServerSocketImpl.java \
	serval/test/TCPServer.java \
	serval/test/TCPClient.java \
	serval/test/UDPServer.java \
	serval/test/UDPClient.java

EXTRA_DIST=

EXTRA_DIST+= $(noinst_JAVA)

JAVAROOT=$(top_builddir)/src/javasock/java

AM_JAVACFLAGS=

clean-local:
	rm -f serval/test/*~
	rm -f serval/net/*~
	rm -f serval/platform/*~
	rm -f *~
	rm -f *.class
	rm -f *.stamp
