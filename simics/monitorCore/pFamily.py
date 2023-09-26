from simics import *
import memUtils
import os
def is_ascii(s):
    return all(ord(c) < 128 for c in s)

class Prec():
    def __init__(self, cpu, proc, tid=None):
        self.cpu = cpu
        self.proc = proc
        self.tid = tid
        self.debugging = False

class Pfamily():
    def __init__(self, cell, param, cpu, mem_utils, task_utils, lgr):
        self.cpu = cpu
        self.cell = cell
        self.param = param
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.prev_parent = None
        self.prev_tabs = ''
        self.lgr = lgr
        self.report_fh = None

    def getPfamily(self):
        retval = []
        cpu, comm, tid = self.task_utils.curThread()
        retval.append(Prec(cpu, comm, tid))
        tasks = self.task_utils.getTaskStructs()
        tabs = ''
        while tid != '0':
            parent_tid, parent_comm, parent_parent = self.parentInfo(tid, tasks)
            if parent_tid is None:
                return retval
            if parent_tid != '0':
                retval.append(Prec(cpu, parent_comm, parent_tid))
            tid = parent_tid
        return retval

    def parentInfo(self, tid, tasks):
        # TBD for windows?
        for t in tasks:
            if str(tasks[t].pid) == tid:
                if tasks[t].group_leader != t:
                    prec_addr = tasks[t].group_leader
                else:
                    prec_addr = tasks[t].parent
                if prec_addr in tasks:
                    return str(tasks[prec_addr].pid), tasks[prec_addr].comm, tasks[prec_addr].parent
                else:
                    break
        return None, None, None

    def execveHap(self, look4_prec, third, forth, memory):
        #cpu = SIM_current_processor()
        #if cpu != look4_prec.cpu:
        #    self.lgr.debug('execveHap, wrong cpu %s %s' % (cpu.name, look4_prec.cpu.name))
        #    return
        cpu, comm, tid = self.task_utils.curThread() 
        prog_string, arg_string_list = self.task_utils.getProcArgsFromStack(tid, None, cpu)
        if look4_prec.proc is not None:
            if prog_string is None:
                return
            fname = os.path.basename(prog_string)
            if not fname.startswith(look4_prec.proc):
                ''' not the proc we are looking for '''
                #self.lgr.debug('%s does not start with %s' % (fname, look4_prec.proc))
                return
            else:
                self.lgr.debug('execveHap found proc we are looking for %s' % prog_string)
        nargs = min(4, len(arg_string_list))
        arg_string = ''
        for i in range(nargs):
            if is_ascii(arg_string_list[i]):
                arg_string += arg_string_list[i]+' '
            else:
                break
        pfamily = self.getPfamily()
        dumb = pfamily.pop(0)
        flen = len(pfamily)
        if flen > 0:
            self.lgr.debug('flen is %d, parent_tid is %s  prev %s' % (flen, pfamily[0].tid, str(self.prev_parent)))
            if pfamily[0].tid != self.prev_parent:
                tabs = ''
                while len(pfamily) > 0:
                    prec = pfamily.pop()
                    self.report_fh.write('%s%5s  %s\n' % (tabs, prec.tid, prec.proc))
                    tabs += '\t'
                    self.prev_parent = prec.tid
                self.report_fh.write('%s%5s  %s %s\n' % (tabs, tid, prog_string, arg_string))
                self.prev_tabs = tabs
            else:
                self.report_fh.write('%s%5s  %s %s\n' % (self.prev_tabs, tid, prog_string, arg_string))
        else:
            self.report_fh.write('%s %s\n' % (prog_string, arg_string))
            self.prev_parent = None
            self.prev_tabs = ''
        if look4_prec.proc is not None:
            self.report_fh.flush() 
            SIM_break_simulation('execve %s' % prog_string)
        #print('execve from %d (%s) prog_string %s' % (tid, comm, prog_string))
        #for arg in arg_string_list:
        #    print(arg)
         

    def traceExecve(self, comm=None):
        look4_prec = Prec(self.cpu, comm, None)
        self.lgr.debug('toExecve set break at 0x%x' % self.param.execve)
        proc_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.execve, self.mem_utils.WORD_SIZE, 0)
        proc_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.execveHap, look4_prec, proc_break)
        self.report_fh = open('/tmp/pfamily.txt', 'w')
