SUBDIRS = java jni
JARFILE = org.servalarch.javasock.jar
MANIFEST = Manifest.txt
javasock_DATA = $(JARFILE)
javasockdir = $(datadir)/java
EXTRA_DIST = $(MANIFEST) README
CLASSFILES = $(shell find java -name *.class -print)

classes.list: $(SUBDIRS) $(CLASSFILES)
	@echo $(CLASSFILES)
	(cd java; find . -name "*.class" -print > ../$@)

sources.list: $(SUBDIRS) $(SOURCEFILES)
	@echo $(SOURCEFILES)
	(cd java; find . -name "*.java" -print > ../$@)

$(JARFILE): classes.list sources.list $(MANIFEST)
	@echo "Creating Jar file"
	(cd java; jar cfm ../$@ ../$(MANIFEST) @../classes.list @../sources.list)

clean-local:
	rm -f *~
	rm -f $(JARFILE)
	rm -f classes.list
	rm -f sources.list
