#
# Makefile for monitorLibs, interaction with zookeeper
# and other lowest layer libs
#
PACKAGE_NAME = cgc-monitor-libs
PY_MODS = szk.py utils.py configMgr.py forensicEvents.py putMonitor.py replayMgr.py teamSets.py accessSQL.py cbConfig.py updateMasterCfg.py programSections.py packageMgr.py getMonitor.py dbgQueue.py throwMgr.py bitArray.py povJson.py cfeCsetConfig.py findPair.py cfeScores.py __init__.py gameThrowJson.py analysisEvents.py traceCycles.py
PY_DIR = $(DESTDIR)/usr/local/lib/python2.7/dist-packages/monitorLibs
MAN = $(PACKAGE_NAME).1.gz
MANDIR = $(DESTDIR)/usr/share/man/man1

%.1.gz: %.md
	pandoc -s -t man $< -o $<.tmp
	gzip -9 < $<.tmp > $@

all: man
man: $(MAN)
install: $(BINARY) $(MAN)
	install -d $(DESTDIR)
	install -d $(PY_DIR)
	install $(PY_MODS) $(PY_DIR)

clean:
	-@rm -f $(MAN) *.tmp

distclean: clean

