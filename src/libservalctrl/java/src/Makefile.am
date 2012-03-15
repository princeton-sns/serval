noinst_JAVA = \
	org/servalarch/servalctrl/HostCtrl.java \
	org/servalarch/servalctrl/LocalHostCtrl.java \
	org/servalarch/servalctrl/RemoteHostCtrl.java \
	org/servalarch/servalctrl/HostCtrlCallbacks.java \
	org/servalarch/servalctrl/ServiceInfo.java \
	org/servalarch/servalctrl/ServiceInfoStat.java \
	org/servalarch/servalctrl/TestApp.java

EXTRA_DIST = $(noinst_JAVA)

JAVAROOT = $(top_builddir)/src/libservalctrl/java/bin

AM_JAVACFLAGS=-classpath $(top_builddir)/src/javasock/java:$(top_builddir)/src/libservalctrl/java/src

clean-local:
	rm -f org/servalarch/servalctrl/*~
	rm -f *~
	rm -f *.class
	rm -f *.stamp
