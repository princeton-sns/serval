bin_PROGRAMS = \
	nltest \
	send_udp_packet \
	send_udp_packetn \
	bindtest \
	bindtestn \
	listentest \
	listentestn \
	udp_server \
	udp_servern \
	udp_client \
	udp_clientn

nltest_SOURCES = nltest.c

send_udp_packet_SOURCES = send_udp_packet.c
send_udp_packet_CPPFLAGS =-I$(top_srcdir)/include
send_udp_packet_LDFLAGS =-L$(top_srcdir)/src/libscaffold -lscaffold

send_udp_packetn_SOURCES = send_udp_packet.c
send_udp_packetn_CPPFLAGS =-DSCAFFOLD_NATIVE -I$(top_srcdir)/include
send_udp_packetn_LDFLAGS =-L$(top_srcdir)/src/libscaffold -lscaffold

bindtest_SOURCES = bindtest.c
bindtest_CPPFLAGS =-I$(top_srcdir)/include
bindtest_LDFLAGS =-L$(top_srcdir)/src/libscaffold -lscaffold

bindtestn_SOURCES = bindtest.c
bindtestn_CPPFLAGS =-DSCAFFOLD_NATIVE -I$(top_srcdir)/include
bindtestn_LDFLAGS =-L$(top_srcdir)/src/libscaffold -lscaffold

listentest_SOURCES = listentest.c
listentest_CPPFLAGS =-I$(top_srcdir)/include
listentest_LDFLAGS =-L$(top_srcdir)/src/libscaffold -lscaffold

listentestn_SOURCES = listentest.c
listentestn_CPPFLAGS =-DSCAFFOLD_NATIVE -I$(top_srcdir)/include
listentestn_LDFLAGS =-L$(top_srcdir)/src/libscaffold -lscaffold

udp_server_SOURCES = udp_server.c
udp_server_CPPFLAGS =-I$(top_srcdir)/include
udp_server_LDFLAGS =-L$(top_srcdir)/src/libscaffold -lscaffold

udp_servern_SOURCES = udp_server.c
udp_servern_CPPFLAGS =-DSCAFFOLD_NATIVE -I$(top_srcdir)/include
udp_servern_LDFLAGS =-L$(top_srcdir)/src/libscaffold -lscaffold

udp_client_SOURCES = udp_client.c
udp_client_CPPFLAGS =-I$(top_srcdir)/include
udp_client_LDFLAGS =-L$(top_srcdir)/src/libscaffold -lscaffold

udp_clientn_SOURCES = udp_client.c
udp_clientn_CPPFLAGS =-DSCAFFOLD_NATIVE -I$(top_srcdir)/include
udp_clientn_LDFLAGS =-L$(top_srcdir)/src/libscaffold -lscaffold

clean-local:
	rm -f *~