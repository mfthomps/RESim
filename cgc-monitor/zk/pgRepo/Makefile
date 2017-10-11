#
# Makefile for pgRepo, interaction with the scoring database
#
PACKAGE_NAME = cgc-monitor-pg-repo
GET_SUBMITS = getSubmits
USER_BIN =  deleteMitTunnel mitTunnel getCsets getSubmits showEvents pkgStatus
PY_MODS = cutils.py models.py pgVet.py pgCsets.py pgSubmits.py __init__.py
BIN_DIR = $(DESTDIR)/usr/bin
PY_DIR = $(DESTDIR)/usr/local/lib/python2.7/dist-packages/pgRepo
PY_TEST_DIR = $(DESTDIR)/usr/local/lib/python2.7/dist-packages/monitorTesting
TEST_MODS = tests/testData.py tests/testSubmits.py __init__.py
MAN = $(GET_SUBMITS).1.gz
MANDIR = $(DESTDIR)/usr/share/man/man1

%.1.gz: %.md
	pandoc -s -t man $< -o $<.tmp
	gzip -9 < $<.tmp > $@

all: man 
man: $(MAN)
install: $(BINARY) $(MAN)
	ls -la $(MAN)
	install -d $(PY_TEST_DIR)
	install $(TEST_MODS) $(PY_TEST_DIR)
	install -d $(BIN_DIR)
	install $(USER_BIN) $(BIN_DIR)
	install -d $(PY_DIR)
	install $(PY_MODS) $(PY_DIR)
	install -d $(MANDIR)
	install $(MAN) $(MANDIR)

clean:
	-@rm -f $(MAN) *.tmp

distclean: clean

