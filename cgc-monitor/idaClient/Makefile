#
# Makefile for pgRepo, interaction with the scoring database
#
PACKAGE_NAME = cgc-ida-client
USER_BIN = oneThrow.py startIda.sh monitorTunnel.sh checkMonitorEnv.sh checkProxies.sh killProxies.sh clearClient.sh clearThrows.py gdbSSHProxy.sh get_monitor_key.sh update-cgc-monitor
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

