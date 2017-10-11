#
# Makefile for demoRepo, manage test repos
#
PACKAGE_NAME = cgc-monitor-demo-repo
UPDATE_TREE = updateTree
CLEAR_ZK = clearZk
USER_BIN = partialCB3 $(UPDATE_TREE) $(CLEAR_ZK) fullCB getCFE_CSET_IDs.sh getCFE_CSET_IDs_actual.py expandSets.py sortLatestSets.py mkNewCBList.py
BIN_DIR = $(DESTDIR)/usr/bin
PY_MODS = testRepo.py
PY_DIR = $(DESTDIR)/usr/local/lib/python2.7/dist-packages/monitorLibs
CGC_SHARE = $(DESTDIR)/usr/share/cgc-monitor
SHARE_FILES = allCFE-CSETS.txt
MAN = $(UPDATE_TREE).1.gz $(CLEAR_ZK).1.gz
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
	install -d $(PY_DIR)
	install $(PY_MODS) $(PY_DIR)
	install -d $(CGC_SHARE)
	install $(SHARE_FILES) $(CGC_SHARE)
	install -d $(MANDIR)
	install $(MAN) $(MANDIR)

clean:
	-@rm -f $(MAN) *.tmp

distclean: clean

