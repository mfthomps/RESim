#
# Makefile for pgRepo, interaction with the scoring database
#
PACKAGE_NAME = cgc-monitor-utils
REPORT_SQL = reportSQL
LIST_MONITOR = listMonitor
RUN_EVENT = runEvent
SHUTDOWN_MONITOR = shutdownMonitor
STOP_MONITOR = stopMonitor
GDB_THROW = gdbThrow
USER_BIN =  $(REPORT_SQL) $(LIST_MONITOR) clearDB-CB clearDB updateAllMasterCfgs rebuildSqlTables cleanCBs $(SHUTDOWN_MONITOR) monitorUtils clearLogs cleanZkNodes targetIP checkMasterCfg putReplayCfg putServiceCfg clearPackages collect4TargetStage mountVmLib mountArtifacts waitnet putMonitorCfg dumpMonitorCfg timeFromMaster clearFileRepo getMyLicenses listRepo $(RUN_EVENT) $(STOP_MONITOR) tarBallCBs checkVMX collectArtifacts killCollectArtifacts continueEvent extractTrace updateCcTables rebuildCcTables killVagrantTalkers $(GDB_THROW) saveDB  killPutCfg zkStatus free.sh killMonitorWatcher runCFE resetGame continueCFE listGames syncFromSpace.py cfeFlow isMonitorDown monitorStatus putOneFromSet putOneFromGame putOnePackage listCFE vizPovs forceQuitReplay restartCFE removeOldConfigCFE.py idaServerDebugSessions.sh schedule.py refVersusRCBs.py forensicsMap.py autoClient.py analysisDump.py
BIN_DIR = $(DESTDIR)/usr/bin
CFG_DIR = $(DESTDIR)/etc/cgc-monitor 
CFG_FILES = monitorCfgOverrides.cfg fabManage.py schedule.json cbmap.txt score_data.csv csid_up_list.json
MAN = $(REPORT_SQL).1.gz $(LIST_MONITOR).1.gz cgc-monitor.1.gz $(RUN_EVENT).1.gz $(SHUTDOWN_MONITOR).1.gz $(STOP_MONITOR).1.gz $(GDB_THROW).1.gz 
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
	install -d $(CFG_DIR)
	install $(CFG_FILES) $(CFG_DIR)
	install -d $(MANDIR)
	install $(MAN) $(MANDIR)

clean:
	-@rm -f $(MAN) *.tmp

distclean: clean

