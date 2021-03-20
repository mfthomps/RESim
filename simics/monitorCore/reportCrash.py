from simics import *
import cli
import sys
import os
import glob
import re
import decode
import decodeArm

class ReportCrash():
    def __init__(self, top, cpu, dataWatch, mem_utils, target, lgr):
        self.top = top
        self.cpu = cpu
        self.lgr = lgr
        self.dataWatch = dataWatch
        self.mem_utils = mem_utils
        self.flist = []
        self.target = target
        if os.path.isfile(target):
            self.flist.append(target)
        else:
            afl_output = os.getenv('AFL_OUTPUT')
            if afl_output is None:
                afl_output = os.path.join(os.getenv('HOME'), 'SEED','afl','afl-output')
            afl_dir = os.path.join(afl_output, target,'crashes*')
            gmask = '%s/*' % afl_dir
            glist = glob.glob(gmask)
            for g in glist:
                if os.path.basename(g).startswith('id:'):
                    self.flist.append(g)
        self.report_dir = '/tmp/crash_reports'
        try:
            os.makedirs(self.report_dir)
        except:
            pass
        self.index = 0
        self.crash_report = None
        if self.cpu.architecture == 'arm':
            self.decode = decodeArm
        else:
            self.decode = decode
        #self.afl_list = [f for f in os.listdir(self.afl_dir) if os.path.isfile(os.path.join(self.afl_dir, f))]
        #self.crash_report = open('/tmp/crash_report.txt', 'w')

    def go(self):
        if self.index < len(self.flist):
            report_file = 'crash_report_%05d' % self.index
            self.crash_report = open(os.path.join(self.report_dir, report_file), 'w')
      
            SIM_run_alone(self.goAlone, None)

    def goAlone(self, dumb):
        self.dataWatch.clearWatchMarks()
        self.top.setCommandCallback(self.doneForward)
        self.crash_report.write("Crash report for %s\n" % self.flist[self.index])
        self.lgr.debug('reportCrash goAlone start for file %s' % self.flist[self.index])
        self.top.injectIO(self.flist[self.index], keep_size = True)

    def doneBackward(self, dumb):
        self.crash_report.write("\n\nBacktrace:\n")
        orig_stdout = sys.stdout
        sys.stdout = self.crash_report
        self.top.listBookmarks()
        self.top.setCommandCallback(None)
        sys.stdout = orig_stdout 
        self.crash_report.close()
        self.index += 1
        self.go() 

    def tryCorruptRef(self, instruct):
        op2, op1 = self.decode.getOperands(instruct[1])
        self.lgr.debug('reportCrash op2: %s op1: %s' % (op2, op1))
        reg_find = re.findall(r'\[.*?\]', op2) 
        self.lgr.debug('reportCrash found in brackets %s' % str(reg_find))
        if len(reg_find) > 0:
            brack_str = reg_find[0].strip()[1:-1]
            if ',' in brack_str: 
                ''' TBD FIXME '''
                reg = brack_str.split(',')[0].strip()
            else:
                reg = brack_str
            if self.mem_utils.isReg(reg):
                self.top.revTaintReg(reg)
            else:
                self.lgr.debug('reportCrash not a reg %s' % reg)
                self.top.setCommandCallback(None)
    
        else:
            self.lgr.debug('reportCrash no regs in %s' % op2)
            self.top.setCommandCallback(None)

    def reportStack(self):
        self.crash_report.write('Stack trace:\n')
        orig_stdout = sys.stdout
        st = self.top.getStackTraceQuiet()
        sys.stdout = self.crash_report
        st.printTrace()
        self.crash_report.flush()
        sys.stdout = orig_stdout 

    def doneForward(self, dumb):
        eip = self.top.getEIP()
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        bad_addr = self.top.getSEGVAddr()
        is_rop = False
        if bad_addr is not None:
            self.crash_report.write("SEGV on access to address: 0x%x\n" % bad_addr)
            SIM_run_command('pselect %s' % self.cpu.name)
            SIM_run_command('skip-to cycle=%d' % (self.cpu.cycles - 1))
            self.reportStack()
            SIM_run_command('pselect %s' % self.cpu.name)
            SIM_run_command('skip-to cycle=%d' % (self.cpu.cycles + 1))
        else:
            bad_addr = self.top.getROPAddr()
            if bad_addr is not None:
                self.crash_report.write("ROP on stack addr: 0x%x\n" % bad_addr)
                is_rop = True
            else:
                self.lgr.error('crashReport doneForward did not find a SEGV or ROP')
                self.top.setCommandCallback(None)
                return            
        self.lgr.debug('reportCrash doneForward eip: 0x%x instruction %s' %(eip, instruct[1]))
        if is_rop:
            self.top.setCommandCallback(self.doneBackward)
            self.lgr.debug('reportCrash stack return address')
            SIM_run_command('pselect %s' % self.cpu.name)
            SIM_run_command('skip-to cycle=%d' % (self.cpu.cycles - 1))
            self.reportStack()
            SIM_run_command('pselect %s' % self.cpu.name)
            SIM_run_command('skip-to cycle=%d' % (self.cpu.cycles + 1))
            self.top.revTaintAddr(bad_addr)
       
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
            if copy_mark is not None:
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
                            self.lgr.debug('reportCrash overlap, rev to find r1')
                            self.top.revTaintAddr(copy_mark.mark.src)
                        else:
                            self.lgr.debug('reportCrash: Is strcpy, but not an overlap')
                    else:
                        self.lgr.debug('reportCrash: Is strcpy, src > dest')
                else:
                    self.lgr.debug('reportCrash, not a strcpy not handled.') 

            else:
                self.lgr.debug('reportCrash not a copy mark, look for bad reference.')
                self.tryCorruptRef(instruct)
           
        #SIM_run_alone(self.goAlone, None)
