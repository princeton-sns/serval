noinst_JAVA = \
	org/servalarch/servalctrl/HostCtrl.java \
	org/servalarch/servalctrl/LocalHostCtrl.java \
	org/servalarch/servalctrl/RemoteHostCtrl.java \
	org/servalarch/servalctrl/HostCtrlCallbacks.java \
	org/servalarch/servalctrl/ServiceInfo.java \
	org/servalarch/servalctrl/ServiceInfoStat.java \
	org/servalarch/servalctrl/FlowStat.java \
	org/servalarch/servalctrl/FlowTCPStat.java \
	org/servalarch/servalctrl/TestApp.java

EXTRA_DIST = $(noinst_JAVA)

JAVAROOT=$(top_srcdir)/src/libservalctrl/java/bin

AM_JAVACFLAGS=-classpath $(top_srcdir)/src/javasock/java:$(top_srcdir)/src/libservalctrl/java/bin

BUILT_SOURCES = ../bin

../bin:
	mkdir $(JAVAROOT)

clean-local:
	rm -rf $(JAVAROOT)
	rm -f org/servalarch/servalctrl/*~
	rm -f *~
	rm -f *.class
	rm -f *.stamp
