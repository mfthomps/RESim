#
# Makefile for monitorLibs, interaction with zookeeper
# and other lowest layer libs
#
PACKAGE_NAME = cgc-monitor-core
PY_MODS = bsdProcessUtils.py bsdUtils.py callLog.py cellConfig.py cellInfo.py cgcEvents.py cgcMonitor.py chainHap.py contextManager.py debugInfo.py debugSignal.py decode.py delayUntilBoot.py errRepo.py findKernelWrite.py getSymbol.py hapManager.py __init__.py kernelInfo.py launchMonitor.py linuxProcessUtils.py linuxUtils.py masterConfig.py memUtils.py notCode.py noX.py osUtils.py otherFaults.py pageFaults.py pageUtils.py procInfo.py protectedInfo.py protectedMemory.py reverseToCall.py reverseToWhatever.py ropCop.py runToUserSpace.py startDebugging2.py startDebugging.py stopHap.py stopHapCallback.py taintManager.py targetLog.py tracing.py watchKernel.py watchLinuxCreds.py backStop.py watchUID.py codeCoverage.py  keepAlive.py negotiatePoV.py debugType2.py bsdParams.py bsd64Params.py bookmarkMgr.py bsdUnexpected.py linux64Params.py returnToUserHap.py runToSyscall.py isMonitorRunning.py reverseToAddr.py AutoAnalysis.py doWhitelist.py
PY_DIR = $(DESTDIR)/usr/local/lib/python2.7/dist-packages/monitorCore
CFG_DIR = $(DESTDIR)/usr/share/cgc-monitor
CFG = master.cfg master_vet.cfg master_viz.cfg master_dbg.cfg master_pov.cfg master_cc.cfg replay_master.xml service_master.xml 
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
	install -d $(CFG_DIR)
	install $(CFG) $(CFG_DIR)

clean:
	-@rm -f $(MAN) *.tmp

distclean: clean

