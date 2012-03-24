bin_PROGRAMS = \
	send_udp_packet_user \
	send_udp_packet \
	recv_udp_packet_user \
	recv_udp_packet \
	bindtest_user \
	bindtest \
	listentest_user \
	listentest \
	udp_server_user \
	udp_server \
	udp_client_user \
	udp_client \
	manysockets

if HAVE_SSL
bin_PROGRAMS += \
	tcp_server_user \
	tcp_server \
	tcp_client_user \
	tcp_client
endif

if OS_LINUX
bin_PROGRAMS += \
	nltest \
	automigrated

nltest_SOURCES = nltest.c

automigrated_SOURCES = automigrated.c
automigrated_CPPFLAGS =-I$(top_srcdir)/include
automigrated_LDFLAGS =-L$(top_srcdir)/src/libservalctrl -lservalctrl

endif

manysockets_CPPFLAGS =-I$(top_srcdir)/include 
manysockets_LDFLAGS =

send_udp_packet_user_SOURCES = send_udp_packet.c
send_udp_packet_user_CPPFLAGS =-I$(top_srcdir)/include
send_udp_packet_user_LDFLAGS =-L$(top_srcdir)/src/libserval -lserval

send_udp_packet_SOURCES = send_udp_packet.c
send_udp_packet_CPPFLAGS =-DSERVAL_NATIVE -I$(top_srcdir)/include
send_udp_packet_LDFLAGS =

recv_udp_packet_user_SOURCES = recv_udp_packet.c
recv_udp_packet_user_CPPFLAGS =-I$(top_srcdir)/include
recv_udp_packet_user_LDFLAGS =-L$(top_srcdir)/src/libserval -lserval

recv_udp_packet_SOURCES = recv_udp_packet.c
recv_udp_packet_CPPFLAGS =-DSERVAL_NATIVE -I$(top_srcdir)/include
recv_udp_packet_LDFLAGS =

bindtest_user_SOURCES = bindtest.c
bindtest_user_CPPFLAGS =-I$(top_srcdir)/include
bindtest_user_LDFLAGS =-L$(top_srcdir)/src/libserval -lserval

bindtest_SOURCES = bindtest.c
bindtest_CPPFLAGS =-DSERVAL_NATIVE -I$(top_srcdir)/include
bindtest_LDFLAGS =

listentest_user_SOURCES = listentest.c
listentest_user_CPPFLAGS =-I$(top_srcdir)/include
listentest_user_LDFLAGS =-L$(top_srcdir)/src/libserval -lserval

listentest_SOURCES = listentest.c
listentest_CPPFLAGS =-DSERVAL_NATIVE -I$(top_srcdir)/include
listentest_LDFLAGS =

udp_server_user_SOURCES = udp_server.c
udp_server_user_CPPFLAGS =-I$(top_srcdir)/include
udp_server_user_LDFLAGS =-L$(top_srcdir)/src/libserval -lserval

udp_server_SOURCES = udp_server.c
udp_server_CPPFLAGS =-DSERVAL_NATIVE -I$(top_srcdir)/include
udp_server_LDFLAGS =-L$(top_srcdir)/src/libserval -lserval

udp_client_user_SOURCES = udp_client.c
udp_client_user_CPPFLAGS =-I$(top_srcdir)/include
udp_client_user_LDFLAGS =-L$(top_srcdir)/src/libserval -lserval

udp_client_SOURCES = udp_client.c
udp_client_CPPFLAGS =-DSERVAL_NATIVE -I$(top_srcdir)/include
udp_client_LDFLAGS =

if HAVE_SSL
tcp_client_user_SOURCES = tcp_client.c common.c
tcp_client_user_CPPFLAGS =-I$(top_srcdir)/include $(OPENSSL_INCLUDES)
tcp_client_user_LDFLAGS =-L$(top_srcdir)/src/libserval -lserval $(OPENSSL_LDFLAGS) -lcrypto

tcp_client_SOURCES = tcp_client.c common.c
tcp_client_CPPFLAGS =-DSERVAL_NATIVE -I$(top_srcdir)/include $(OPENSSL_INCLUDES)
tcp_client_LDFLAGS =$(OPENSSL_LDFLAGS) -lcrypto

tcp_server_user_SOURCES = tcp_server.c common.c
tcp_server_user_CPPFLAGS =-I$(top_srcdir)/include $(OPENSSL_INCLUDES)
tcp_server_user_LDFLAGS =-L$(top_srcdir)/src/libserval -lserval $(OPENSSL_LDFLAGS) -lcrypto

tcp_server_SOURCES = tcp_server.c common.c
tcp_server_CPPFLAGS =-DSERVAL_NATIVE -I$(top_srcdir)/include $(OPENSSL_INCLUDES)
tcp_server_LDFLAGS =$(OPENSSL_LDFLAGS) -lcrypto
endif

noinst_HEADERS = \
	common.h

EXTRA_DIST = README Android.mk

clean-local:
	rm -f *~
