#
# makefile for monitoring scripts that will run on the simulated target
#
PACKAGE_NAME    = cgc-monitor-target-base
USER_BIN              = doTFTP.sh putTFTP.sh dodate.sh runReplayMaster.sh
SERVICE               = initReplay
MAN                             = $(SERVICE).1.gz
BIN                     = $(DESTDIR)/usr/bin
MANDIR                  = $(DESTDIR)/usr/share/man/man1
INITD                  = $(DESTDIR)/etc/init.d

%.1.gz: %.md
	pandoc -s -t man $< -o $<.tmp
	gzip -9 < $<.tmp > $@

man: $(MAN)
install: $(BINARY) $(MAN)
	ls -la $(MAN)
	install -d $(BIN)
	install $(USER_BIN) $(BIN)
	install -d $(INITD)
	install $(SERVICE) $(INITD)
	install -d $(MANDIR)
	install $(MAN) $(MANDIR)

clean:
	-@rm -f $(MAN) *.tmp

distclean: clean
