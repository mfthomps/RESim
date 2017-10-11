#
# Makefile for monitor services
#
PACKAGE_NAME = cgc-monitor-services
PUT_PACKAGES = putPackages
TARGET_WATCHER = targetWatcher
DEATH_WATCH = deathWatch
UPDATE_SQL = updateSQL
UPDATE_DB_LOGS = updateDBLogs
USER_BIN =  $(PUT_PACKAGES) $(DEATH_WATCH) $(TARGET_WATCHER) $(UPDATE_SQL) $(UPDATE_DB_LOGS) 
BIN_DIR = $(DESTDIR)/usr/bin
PY_DIR = $(DESTDIR)/usr/local/lib/python2.7/dist-packages/pgRepo
SERVICE_DIR = $(DESTDIR)/etc/init.d
SERVICES = logUpdateService sqlUpdateService
MAN = $(PUT_PACKAGES).1.gz $(TARGET_WATCHER).1.gz $(DEATH_WATCH).1.gz
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
	install $(SERVICES) $(SERVICE_DIR)
	install -d $(MANDIR)
	install $(MAN) $(MANDIR)

clean:
	-@rm -f $(MAN) *.tmp

distclean: clean

