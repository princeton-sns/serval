bin_PROGRAMS = \
	send_udp_packet \
	send_udp_packetn \
	recv_udp_packet \
	recv_udp_packetn \
	bindtest \
	bindtestn \
	listentest \
	listentestn \
	udp_server \
	udp_servern \
	udp_client \
	udp_clientn \
	tcp_inet_client \
	addservice

if OS_LINUX
bin_PROGRAMS += \
	nltest \
	translator

nltest_SOURCES = nltest.c

translator_SOURCES = translator.c
translator_CPPFLAGS =-I$(top_srcdir)/include
translator_LDFLAGS =-lpthread

endif

addservice_SOURCES = addservice.c
addservice_CPPFLAGS =-I$(top_srcdir)/include -I$(top_srcdir)/src/libstack
addservice_LDFLAGS =-L$(top_srcdir)/src/libstack -lstack

tcp_inet_client_SOURCES = tcp_inet_client.c

send_udp_packet_SOURCES = send_udp_packet.c
send_udp_packet_CPPFLAGS =-I$(top_srcdir)/include
send_udp_packet_LDFLAGS =-L$(top_srcdir)/src/libserval -lserval

send_udp_packetn_SOURCES = send_udp_packet.c
send_udp_packetn_CPPFLAGS =-DSERVAL_NATIVE -I$(top_srcdir)/include
send_udp_packetn_LDFLAGS =

recv_udp_packet_SOURCES = recv_udp_packet.c
recv_udp_packet_CPPFLAGS =-I$(top_srcdir)/include
recv_udp_packet_LDFLAGS =-L$(top_srcdir)/src/libserval -lserval

recv_udp_packetn_SOURCES = recv_udp_packet.c
recv_udp_packetn_CPPFLAGS =-DSERVAL_NATIVE -I$(top_srcdir)/include
recv_udp_packetn_LDFLAGS =

bindtest_SOURCES = bindtest.c
bindtest_CPPFLAGS =-I$(top_srcdir)/include
bindtest_LDFLAGS =-L$(top_srcdir)/src/libserval -lserval

bindtestn_SOURCES = bindtest.c
bindtestn_CPPFLAGS =-DSERVAL_NATIVE -I$(top_srcdir)/include
bindtestn_LDFLAGS =

listentest_SOURCES = listentest.c
listentest_CPPFLAGS =-I$(top_srcdir)/include
listentest_LDFLAGS =-L$(top_srcdir)/src/libserval -lserval

listentestn_SOURCES = listentest.c
listentestn_CPPFLAGS =-DSERVAL_NATIVE -I$(top_srcdir)/include
listentestn_LDFLAGS =

udp_server_SOURCES = udp_server.c
udp_server_CPPFLAGS =-I$(top_srcdir)/include
udp_server_LDFLAGS =-L$(top_srcdir)/src/libserval -lserval

udp_servern_SOURCES = udp_server.c
udp_servern_CPPFLAGS =-DSERVAL_NATIVE -I$(top_srcdir)/include
udp_servern_LDFLAGS =-L$(top_srcdir)/src/libserval -lserval

udp_client_SOURCES = udp_client.c
udp_client_CPPFLAGS =-I$(top_srcdir)/include
udp_client_LDFLAGS =-L$(top_srcdir)/src/libserval -lserval

udp_clientn_SOURCES = udp_client.c
udp_clientn_CPPFLAGS =-DSERVAL_NATIVE -I$(top_srcdir)/include
udp_clientn_LDFLAGS =

clean-local:
	rm -f *~
