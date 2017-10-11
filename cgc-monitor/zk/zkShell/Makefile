#
# Makefile for pgRepo, interaction with the scoring database
#
PACKAGE_NAME = cgc-monitor-zk-shell
ZK_M_DIR = $(DESTDIR)/mnt/cgc/zk/zkShell
ZK_M_CONF_DIR = $(ZK_M_DIR)/conf
ZK_M_BIN_DIR = $(ZK_M_DIR)/bin
ZK_M_BUILD_DIR = $(ZK_M_DIR)/build
ZK_M_CLASSES_DIR = $(ZK_M_BUILD_DIR)/classes
ZK_M_LIB_DIR = $(ZK_M_BUILD_DIR)/lib
ZK_BINS = bin/zkEnv.sh bin/startZshell.sh
ZK_CONF = conf/configuration.xsl conf/log4j.properties
CLASSES = build/classes/*
LIB_DIR = /usr/lib/monitorJavaLibJars
ZK_M_LIB_DIR = $(ZK_M_DIR)/lib
SERVICE_DIR = $(DESTDIR)/etc/init.d
SERVICE = zkShellService
MAN = zkShell.1.gz 
MANDIR = $(DESTDIR)/usr/share/man/man1

%.1.gz: %.md
	pandoc -s -t man $< -o $<.tmp
	gzip -9 < $<.tmp > $@

all: ant man
man: $(MAN)
ant:
	ant compile
install: $(BINARY) $(MAN)
	ls -la $(MAN)
	install -d $(ZK_M_DIR)
	install -d $(ZK_M_CONF_DIR)
	install $(ZK_CONF) $(ZK_M_CONF_DIR)
	install -d $(ZK_M_BIN_DIR)
	install $(ZK_BINS) $(ZK_M_BIN_DIR)
	install -d $(ZK_M_BUILD_DIR)
	install -d $(ZK_M_CLASSES_DIR)
	install $(CLASSES) $(ZK_M_CLASSES_DIR)
	install -d $(SERVICE_DIR)
	install $(SERVICE) $(SERVICE_DIR)
	rm -f $(ZK_M_LIB_DIR)
	ln -s -T $(LIB_DIR) $(ZK_M_LIB_DIR)
	install -d $(MANDIR)
	install $(MAN) $(MANDIR)

clean:
	-@rm -f $(MAN) *.tmp

distclean: clean

