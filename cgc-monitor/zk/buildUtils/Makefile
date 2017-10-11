#
# Makefile for buildUtils
#
PACKAGE_NAME = cgc-monitor-build-utils
USER_BIN = collectPackages updatePackages monitorSlaveBootstrap collectFromArtifacts getMonitorPackage zkInstance cpToVagrant getMyIp startServiceOnTargets atomicCp.sh latestImages.sh getKernelSymbols noTxcsum killHungScp monitorRamWatcher createSimicsUpdate.sh 
#
# These are scripts that get installed on targets, they live in /usr/share so they can be found.  Not executed from there!
#
TARGET_SCRIPTS = prepTarget runReplayMaster.sh runServiceMaster.sh runIDS.sh runOneBox.sh dodate.sh noOffload.sh id_rsa id_rsa.pub interfaces.5 interfaces.6 interfaces.7 freezeOrGo.sh startService ksections.py bsdKSections.sh portListening getUname.sh getKernelSymbolsOnTarget replay_wrapper.sh
BIN_DIR = $(DESTDIR)/usr/bin
TARGET_SCRIPTS_DIR = $(DESTDIR)/usr/share/cgc-monitor
SERVICE_DIR = $(DESTDIR)/etc/init.d
SERVICE = monitorSlaveService
MAN = $(PACKAGE_NAME).1.gz
MANDIR = $(DESTDIR)/usr/share/man/man1

%.1.gz: %.md
	pandoc -s -t man $< -o $<.tmp
	gzip -9 < $<.tmp > $@

all: man
man: $(MAN)
install: $(BINARY) $(MAN)
	ls -la $(MAN)
	install -d $(BIN_DIR)
	install $(USER_BIN) $(BIN_DIR)
	install -d $(SERVICE_DIR)
	install $(SERVICE) $(SERVICE_DIR)
	install -d $(TARGET_SCRIPTS_DIR)
	install $(TARGET_SCRIPTS) $(TARGET_SCRIPTS_DIR)
	install -d $(MANDIR)
	install $(MAN) $(MANDIR)

clean:
	-@rm -f $(MAN) *.tmp

distclean: clean

