#
# Makefile for headerUtils
#
PACKAGE_NAME = cgc-monitor-header-utils
USER_BIN =  buildCfg2.py readcgcef-minimal.py
BIN_DIR = $(DESTDIR)/usr/bin
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
	install -d $(MANDIR)
	install $(MAN) $(MANDIR)

clean:
	-@rm -f $(MAN) *.tmp

distclean: clean

