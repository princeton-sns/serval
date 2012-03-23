SUBDIRS = \
	jni \
	src

JARFILE = org.servalarch.servalctrl.jar
MANIFEST = Manifest.txt
javasock_DATA = $(JARFILE)
javasockdir = $(datadir)/java
EXTRA_DIST = $(MANIFEST)
CLASSFILES = $(shell find ./bin -name *.class -print)

classes.list: $(SUBDIRS) $(CLASSFILES) 
	@echo $(CLASSFILES)
	(cd bin; find . -name "*.class" -print > ../$@)

sources.list: $(SUBDIRS) $(SOURCEFILES)
	@echo $(SOURCEFILES)
	(cd src; find . -name "*.java" -print > ../$@)

$(JARFILE): classes.list sources.list $(MANIFEST)
	@echo "Creating Jar file"
	(cd bin; jar cfm ../$@ ../$(MANIFEST) @../classes.list)
	(cd src; jar uf ../$@ @../sources.list)

clean-local:
	rm -rf bin
	rm -f *~
	rm -f $(JARFILE)
	rm -f classes.list
	rm -f sources.list
