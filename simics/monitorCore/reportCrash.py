from simics import *
import cli
import sys
import os
import glob
import re
import decode
import decodeArm
import decodePPC32
import pageUtils
import aflPath

class ReportCrash():
    def __init__(self, top, cpu, tid, dataWatch, mem_utils, fname, num_packets, one_done, report_index, lgr, 
                    target=None, targetFD=None, trackFD=None, report_dir=None):
        self.top = top
        self.cpu = cpu
        
        self.cell_name = self.top.getTopComponentName(cpu)
        self.tid = tid
        self.lgr = lgr
        self.report_index = report_index
        self.one_done = one_done
        self.dataWatch = dataWatch
        self.mem_utils = mem_utils
        self.flist = []
        self.fname = fname
        self.num_packets = num_packets
        self.target = target
        self.targetFD = targetFD
        self.index = 0
        if os.path.isfile(fname):
            self.flist.append(fname)
        else:
            self.flist = aflPath.getTargetCrashes(fname)
        if report_dir is None:
            self.report_dir = '/tmp/crash_reports'
        else:
            self.report_dir = report_dir
        try:
            os.makedirs(self.report_dir)
        except:
            pass
        self.crash_report = None
        self.report_path = None
        if self.cpu.architecture.startswith('arm'):
            self.decode = decodeArm
        elif self.cpu.architecture == 'ppc32':
            self.decode = decodePPC32
        else:
            self.decode = decode
        ''' Will be None if ReportCrash to inject data, otherwise the FD to trackIO on '''
        self.trackFD = trackFD

        if self.dataWatch is not None:
            self.dataWatch.setMaxMarksCallback(self.maxMarksCallback)
        self.skip_ip = []
        if os.path.isfile('ignore_crash_ip.txt'):
            with open('ignore_crash_ip.txt') as fh:
                for line in fh:
                    if '#' not in line.strip():
                        addr_s = line.strip()
                        try:
                            self.skip_ip.append(int(addr_s, 16))
                            self.lgr.debug('reportCrash ignore_crash_ip.txt added %s' % addr_s)
                        except:
                            self.lgr.error('reportCrash ignore_crash_ip.txt failed on %s' % line)
                            self.top.quit()
                            

    def go(self):
         if self.index > 0 and self.target is not None:
                self.lgr.debug('reportCrash go, skip to bookmark0')
                SIM_run_command('pselect %s' % self.cpu.name)
                SIM_run_command('skip-to bookmark = bookmark0')
         if self.index < len(self.flist):
            if self.report_index is None:
                report_file = 'crash_report_%05d' % self.index
            else:
                report_file = 'crash_report_%05d' % self.report_index
            self.report_path = os.path.join(self.report_dir, report_file)
            print('Creating crash report at %s' % self.report_path)
            self.lgr.debug('Creating crash report at %s' % self.report_path)
            self.crash_report = open(self.report_path, 'w')
      
            SIM_run_alone(self.goAlone, None)
         else:
            self.lgr.debug('index %d exceeds number of crashes in flist %d' % (self.index, len(self.flist)))
            if self.one_done:
                self.top.quit()

    def goAlone(self, dumb):
        self.dataWatch.clearWatchMarks()
        self.top.setCommandCallback(self.doneForward)
        self.top.resetBookmarks()
        self.top.removeDebugBreaks(immediate=True)

        self.crash_report.write("Crash report for %s\n" % self.flist[self.index])
        self.lgr.debug('********reportCrash goAlone start for file %s' % self.flist[self.index])
        ''' TBD why keep size? '''
        #self.top.injectIO(self.flist[self.index], keep_size = True)
        ''' Either inject or track '''
        if self.trackFD is None:
            self.top.injectIO(self.flist[self.index], keep_size = False, n=self.num_packets, cpu=self.cpu, target=self.target, 
                   targetFD=self.targetFD, callback=self.doneForward, no_iterators=True, no_reset=False, max_marks=400)
            #      targetFD=self.targetFD, callback=self.top.stopTrackIO, no_iterators=True, no_reset=False, max_marks=400)
            #       targetFD=self.targetFD, callback=self.doneForward, no_iterators=True)
        else:
            ''' Be sure we are debugging and then do the trackIO '''
            self.top.debugSnap(final_fun = self.doTrack)

    def doTrack(self):
        SIM_run_command('disable-reverse-execution')
        #self.top.trackIO(self.trackFD, reset=True, callback=self.doneForward)
        self.top.trackIO(self.trackFD, reset=True, callback=top.stopTrackIO)

    def doneBackward(self, dumb):
        self.lgr.debug('crashReport doneBackward')
        try:
            self.crash_report.write("\n\nBacktrace:\n")
        except:
            self.lgr.debug('tbd fix this race in reportCrash')
            return
        orig_stdout = sys.stdout
        sys.stdout = self.crash_report
        self.lgr.debug('crashReport doneBackward now list bookmarks')
        self.top.listBookmarks()
        self.top.setCommandCallback(None)
        sys.stdout = orig_stdout 
        self.crash_report.close()
        print('report written to %s' % self.report_path)
        self.index += 1
        self.lgr.debug('crashReport doneBackward now go index %d' % self.index)
        self.go() 

    def doneNothing(self, dumb):
        self.crash_report.write("\n\nNothing found:\n")
        orig_stdout = sys.stdout
        sys.stdout = self.crash_report
        self.top.setCommandCallback(None)
        sys.stdout = orig_stdout 
        self.crash_report.close()
        self.index += 1
        self.go() 

    def tryCorruptRef(self, instruct, no_increments=False):
        op2, op1 = self.decode.getOperands(instruct[1])
        self.lgr.debug('reportCrash instruct: %s op2: %s op1: %s' % (instruct, op2, op1))
        reg_find = []
        if op2 is not None:
            reg_find = re.findall(r'\[.*?\]', op2) 
            self.lgr.debug('reportCrash found in brackets for %s is %s' % (op2, str(reg_find)))
        if len(reg_find) == 0:
            reg_find = re.findall(r'\[.*?\]', op1) 
            self.lgr.debug('reportCrash found in brackets for %s is %s' % (op1, str(reg_find)))
            if len(reg_find) > 0:
                if op2 is not None and self.mem_utils.isReg(op2):
                    value = self.mem_utils.getRegValue(self.cpu, op2)
                    self.lgr.debug('op2 is reg: %s value: 0x%x' % (op2, value))
                    self.crash_report.write('Corrupt write from reg: %s value: 0x%x\n' % (op2, value))
   
        if len(reg_find) > 0:
            brack_str = reg_find[0].strip()[1:-1]
            if ',' in brack_str: 
                ''' TBD FIXME '''
                reg = brack_str.split(',')[0].strip()
            elif '+' in brack_str: 
                reg = brack_str.split('+')[0].strip()
            else:
                reg = brack_str
            if self.mem_utils.isReg(reg):
                self.top.revTaintReg(reg, no_increments=no_increments)
            else:
                self.lgr.debug('reportCrash not a reg %s' % reg)
                self.top.setCommandCallback(None)
                self.top.quit()
    
        else:
            self.lgr.debug('reportCrash no regs in op2 of %s' % instruct[1])
            self.top.setCommandCallback(None)
            self.top.quit()

    def reportStack(self):
        self.crash_report.write('Stack trace:\n')
        orig_stdout = sys.stdout
        st = self.top.getStackTraceQuiet()
        sys.stdout = self.crash_report
        st.printTrace()
        self.crash_report.flush()
        sys.stdout = orig_stdout 

    def doneForward(self, dumb=None):
        self.top.stopTrackIO()
        eip = self.top.getEIP()
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        bad_addr = self.top.getSEGVAddr()
        if eip in self.skip_ip:
            self.lgr.debug('doneForward got eip in skip list 0x%x' % eip)
            self.crash_report.write('IP: 0x%x in skip list, bad addr 0x%x, ignore' % (eip, bad_addr))
            self.top.quit()
        is_rop = False
        read_count = self.dataWatch.readCount()
        self.crash_report.write('%d read/recv calls prior to crash\n' % read_count)
        if bad_addr is not None:
            self.crash_report.write("SEGV on access to address: 0x%x\n" % bad_addr)
            self.lgr.debug("reportCrash doneForward SEGV on access to address: 0x%x\n" % bad_addr)
            #SIM_run_command('pselect %s' % self.cpu.name)
            #SIM_run_command('skip-to cycle=%d' % (self.cpu.cycles - 1))
            #self.reportStack()
            #SIM_run_command('pselect %s' % self.cpu.name)
            #SIM_run_command('skip-to cycle=%d' % (self.cpu.cycles + 1))
            if instruct[1].startswith('ldm') and 'pc' in instruct[1]:
                SIM_run_command('skip-to cycle=%d' % (self.cpu.cycles + 1))
                eip = self.top.getEIP()
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        elif self.top.getBookmarksInstance() is None:
            self.crash_report.write('Crash prior to reaching target process')
            self.lgr.debug('reportCrash doneForward Crash prior to reaching target process, no bookmarks')
            self.reportStack()
            self.doneBackward(None)
            return
        else:
            bad_addr = self.top.getROPAddr()
            if bad_addr is not None:
                self.crash_report.write("ROP would return to addr: 0x%x\n" % bad_addr)
                is_rop = True
            else:
                bad_addr = self.top.getFaultAddr()
                if bad_addr is not None:
                    self.crash_report.write("Unhandled fault on access to address: 0x%x\n" % bad_addr)
                    self.lgr.debug("reportCrash doneForward Unhandled fault on access to address: 0x%x\n" % bad_addr)
                    self.reportStack()
                else:
                    if self.top.hasPendingPageFault(self.tid):
                        self.lgr.debug("reportCrash doneForward sees there is a pending fault, call pendingFault and return")
                        self.top.pendingFault(target=self.cell_name)
                        return
                    else:
                        self.lgr.error('crashReport doneForward did not find a SEGV or ROP')
                        SIM_run_alone(self.doneNothing,None)
                        return            
        self.lgr.debug('reportCrash doneForward eip: 0x%x instruction %s' %(eip, instruct[1]))
        if is_rop:
            self.top.setCommandCallback(self.doneBackward)
            self.lgr.debug('reportCrash would return to address 0x%x' % bad_addr)
            SIM_run_command('pselect %s' % self.cpu.name)
            #SIM_run_command('skip-to cycle=%d' % (self.cpu.cycles - 1))
            self.reportStack()
            SIM_run_command('pselect %s' % self.cpu.name)
            SIM_run_command('skip-to cycle=%d' % (self.cpu.cycles + 1))
            self.top.revTaintReg('pc')
       
        elif 'illegal' in instruct[1] or 'whole in' in instruct[1]:
            ''' looks like corrupt PC '''
            self.crash_report.write("Corrupt PC\n")
            SIM_run_command('pselect %s' % self.cpu.name)
            SIM_run_command('skip-to cycle=%d' % (self.cpu.cycles - 1))
            self.reportStack()
            SIM_run_command('pselect %s' % self.cpu.name)
            SIM_run_command('skip-to cycle=%d' % (self.cpu.cycles + 1))
            self.top.setCommandCallback(self.doneBackward)
            self.top.revTaintReg('pc')
        else:
            copy_mark = self.dataWatch.getCopyMark()
            ''' iterators may not have call_cycle '''
            if copy_mark is not None and copy_mark.call_cycle is not None:
                ''' In a mem copy function.  Get the parameters,
                    back up to the call, and try to find the source
                    of the length field. '''
                self.reportStack()
                self.lgr.debug('reportCrash was in copy %s' % copy_mark.mark.getMsg()) 
                SIM_run_command('pselect %s' % self.cpu.name)
                SIM_run_command('skip-to cycle=%d' % (copy_mark.call_cycle))
                self.crash_report.write('Access violation in copy function %s\n' % copy_mark.mark.getMsg())
                ''' we are at the call.'''
                if copy_mark.mark.strcpy:
                    self.lgr.debug('reportCrash is strcpy')
                    if copy_mark.mark.dest > copy_mark.mark.src:
                        delta = copy_mark.mark.dest - copy_mark.mark.src 
                        if copy_mark.mark.length > delta:
                            self.crash_report.write('A strcpy buffer overlap.')
                            self.top.setCommandCallback(self.doneBackward)
                            self.lgr.debug('reportCrash overlap, rev to find src address')
                            self.top.revTaintAddr(copy_mark.mark.src)
                        else:
                            self.lgr.debug('reportCrash: Is strcpy, but not an overlap')
                            self.crash_report.write('\nUnknown cause. Was strcpy but not an overlap?\n')
                            self.doneBackward(None)
                    else:
                        self.lgr.debug('reportCrash: Is strcpy, src > dest')
                else:
                    if bad_addr % pageUtils.PAGE_SIZE == 0:
                        self.lgr.debug('reportCrash thinks it is a page boundary in a memcpy type function')
                        self.crash_report.write('\nPage boundary.\n')
                        self.doneBackward(None)
                    else:
                        self.lgr.debug('reportCrash, a strcpy not handled.') 
                        self.crash_report.write('\nUnknown cause.\n')
                        self.doneBackward(None)
            elif bad_addr % pageUtils.PAGE_SIZE == 0:
                self.lgr.debug('reportCrash thinks it is a page boundary')
                self.top.setCommandCallback(self.doneBackward)
                self.reportStack()
                self.crash_report.write('\nPage boundary.\n')
                self.crash_report.flush()
                self.tryCorruptRef(instruct, no_increments=True)
                #self.doneBackward(None)
            else:
                self.lgr.debug('reportCrash not a copy mark, look for bad reference.')
                self.top.setCommandCallback(self.doneBackward)
                self.reportStack()
                self.tryCorruptRef(instruct)
           
        #SIM_run_alone(self.goAlone, None)

    def addMsg(self, msg):
        self.crash_report.write(msg)

    def maxMarksCallback(self):
        self.lgr.debug('reportCrash maxMarksCallback, call pendingFault to check for faults') 
        if not self.top.pendingFault(target=self.cell_name):
            self.lgr.debug('reportCrash maxMarksCallback, just continue') 
            SIM_run_alone(SIM_continue, 0)
        else:
            self.lgr.debug('reportCrash maxMarksCallback, got page fault, call doneForward') 
            self.doneForward()
