#
# Makefile for monitorLibs, interaction with zookeeper
# and other lowest layer libs
#
PACKAGE_NAME = cgc-monitor-simics-scripts
SIMICS_SCRIPTS_DIR = $(DESTDIR)/usr/local/lib/python2.7/dist-packages/simicsScripts
SIMICS_SCRIPTS = traceAfterEIP.py
TARGETS = $(SIMICS_SCRIPTS_DIR)/targets
PLATFORM_DIR = $(TARGETS)/x86-x58-ich10
PLATFORM = targets/x86-x58-ich10/cfe3.simics targets/x86-x58-ich10/cfe1.simics targets/x86-x58-ich10/cfe2.simics targets/x86-x58-ich10/bsd1.simics targets/x86-x58-ich10/cmb1.simics targets/x86-x58-ich10/cmb3.simics
#SIMICS_TARGETS_DIR = $(DESTDIR)/mnt/simics/simics-4.8/simics-x86-core-i7-x58-ich10-4.8.35/targets/x86-x58-ich10
SIMICS_TARGETS_SCRIPTS = targets/x86-x58-ich10/viper-cgc.simics targets/x86-x58-ich10/x86-x58-ich10-system.include
BIN_DIR = $(DESTDIR)/usr/bin
SHARE_DIR = $(DESTDIR)/usr/share/cgc-monitor
SHARE_STUFF = vagrant_insecure_key ssh-config-add vagrant_authorized_key
BINS = monitor.sh monitorDebug.sh hackStdIn.sh monitorFromCkpt.sh clearStdIn monitorDev.sh updateWorkspace.sh prepCFE.sh killSimicsWorkspace killPortListeners sendSimicsWorkspace traceFromEIP vmdkToCraff.sh expectSim.sh
MAN = $(PACKAGE_NAME).1.gz traceFromEIP.1.gz
MANDIR = $(DESTDIR)/usr/share/man/man1

%.1.gz: %.md
	pandoc -s -t man $< -o $<.tmp
	gzip -9 < $<.tmp > $@

all: man
man: $(MAN)
install: $(BINARY) $(MAN)
	install -d $(SIMICS_SCRIPTS_DIR)
	install -d $(TARGETS)
	install -d $(PLATFORM_DIR)
	install $(PLATFORM) $(PLATFORM_DIR)
	install $(SIMICS_SCRIPTS) $(SIMICS_SCRIPTS_DIR)
#	install -d $(SIMICS_TARGETS_DIR)
	install $(SIMICS_TARGETS_SCRIPTS) $(PLATFORM_DIR)
#	install $(SIMICS_TARGETS_SCRIPTS) $(SIMICS_TARGETS_DIR)
	install -d $(SHARE_DIR)
	install $(SHARE_STUFF) $(SHARE_DIR)
	install -d $(BIN_DIR)
	install $(BINS) $(BIN_DIR)
	install -d $(MANDIR)
	install $(MAN) $(MANDIR)



clean:
	-@rm -f $(MAN) *.tmp

distclean: clean

