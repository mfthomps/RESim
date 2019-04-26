#
# Makefile for pgRepo, interaction with the scoring database
#
PACKAGE_NAME = cgc-monitor-ida
SIMICS_DIR = $(DESTDIR)/mnt/cgc/simics
SHARE_DIR = $(DESTDIR)/usr/share/cgc-monitor
IDA_FILES = idaAnalysis.sh idaAnalysis.py functionBlocks.py cgc.til cgc.llx rev.py okTextForm.py gdbProt.py bookmarkView.py waitDialog.py
MAN = $(PACKAGE_NAME).1.gz
MANDIR = $(DESTDIR)/usr/share/man/man1

%.1.gz: %.md
	pandoc -s -t man $< -o $<.tmp
	gzip -9 < $<.tmp > $@

all: man
man: $(MAN)
install: $(BINARY) $(MAN)
	ls -la $(MAN)
	install -d $(SHARE_DIR)
	install $(IDA_FILES) $(SHARE_DIR)
	install -d $(MANDIR)
	install $(MAN) $(MANDIR)

clean:
	-@rm -f $(MAN) *.tmp

distclean: clean

