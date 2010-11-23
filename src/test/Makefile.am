bin_PROGRAMS = nltest send_udp_packet send_udp_packetn bindtest bindtestn

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

clean-local:
	rm -f *~
