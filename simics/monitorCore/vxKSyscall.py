from simics import *
import taskUtils
import net
import vxNet
import syscall
import hapCleaner
from resimHaps import *
class ExitInfo():
    def __init__(self, syscall, stop_on_exit, call_name):
        self.syscall_instance = syscall
        #self.restore_bps = restore_bps
        self.stop_on_exit = stop_on_exit
        self.call_name = call_name
        self.call_params = []
        self.matched_param = None
        self.fname = None
class VxKSyscall():
    def __init__(self, top, cpu, cell_name, mem_utils, task_utils, so_map, call_exit, trace_mgr, context_manager, lgr, call_list=None, call_params=[], 
                   name=None, flist_in=None, linger=False):
        self.cpu = cpu
        self.cell_name = cell_name
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.so_map = so_map
        self.trace_mgr = trace_mgr
        self.call_list = call_list
        self.call_exit = call_exit
        self.call_params = call_params
        self.context_manager = context_manager
        self.top = top
        self.name = name
        self.linger = linger
        self.lgr = lgr
        self.module_bp = []
        self.module_hap = []
        self.global_sym = task_utils.getGlobalSymDict()
        self.sym_hap = None
        self.kbuffer = None
        self.hackme = False
        self.stop_action = None
        self.stop_hap = None
        if self.so_map.inModule():
            self.lgr.debug('vxKSyscall in app, set globals call list %s' % str(call_list))
            self.setGlobal(call_list)
        else:
            self.lgr.debug('vxKSyscall traceAll not in app, set module break')
            self.setModuleBreak()
        self.flist_in = flist_in
        if flist_in is not None:
            ''' Given function list to use after syscall completes '''
            hap_clean = hapCleaner.HapCleaner(cpu)
            #for ph in self.proc_hap:
            #    hap_clean.add("GenContext", ph)
            self.stop_action = hapCleaner.StopAction(hap_clean, flist=flist_in)
            #self.lgr.debug('Syscall cell %s stop action includes given flist_in.  stop_on_call is %r linger: %r name: %s' % (self.cell_name, stop_on_call, self.linger, name))
        else:
            hap_clean = hapCleaner.HapCleaner(cpu)
            self.stop_action = hapCleaner.StopAction(hap_clean)
            #self.lgr.debug('Syscall cell %s stop action includes NO flist linger: %r name: %s' % (self.cell_name, self.linger, name))

    def setGlobal(self, call_list):
        bp_start = None
        bp = None
        for addr in self.global_sym:
            
            #self.lgr.debug('vxKSyscall setGlobal check for %s' % self.global_sym[addr])
            if call_list is None or self.global_sym[addr] in call_list:
                self.lgr.debug('vxKSyscall setGlobal for %s addr 0x%x context %s' % (self.global_sym[addr], addr, self.cpu.current_context))
                #bp = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, addr, 1, 0)
                bp = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, addr, 1, 0)
                if bp_start is None:
                    bp_start = bp
        if bp_start is not None:
            if bp_start != bp:
                #self.sym_hap = SIM_hap_add_callback_range("Core_Breakpoint_Memop", self.symbolHap, None, bp_start, bp)
                self.sym_hap = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.symbolHap, None, bp_start, bp, 'syscall')
                self.lgr.debug('vxKSyscall setGlobal set bp range %d %d' % (bp_start, bp))
            else:
                #self.sym_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.symbolHap, None, bp)
                self.sym_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.symbolHap, None, bp, 'syscall')
                self.lgr.debug('vxKSyscall setGlobal set bp %d' % (bp))

    def parseCall(self, fun, exit_info):
        trace_msg = None
        frame = self.task_utils.frameFromRegs()
        if fun == 'socket':
            domain = frame['param1']
            sock_type = frame['param2']
            protocol = frame['param3']
            domain_name = net.domaintype[domain]
            type_name = net.socktype[sock_type] 
            trace_msg = ('%s domain: %s  type: %s' % (fun, domain_name, type_name))
        if fun == 'ioctl':
            fd = frame['param1']
            cmd = frame['param2']
            arg = frame['param3']
            arg_val = SIM_read_phys_memory(self.cpu, arg, 4)
            FIONBIO = 0x90040010
            if cmd == FIONBIO:
                trace_msg = ('%s fd: 0x%x FIONBIO (set blocking) arg 0x%x arg_val 0x%x' % (fun, fd, arg, arg_val))
            elif cmd == 0x10:
                self.mem_utils.setRegValue(self.cpu, 'r1', FIONBIO)
                trace_msg = ('%s fd: 0x%x FORCED set of FIONBIO (set blocking) arg 0x%x arg_val 0x%x' % (fun, fd, arg, arg_val))
            else:
                trace_msg = ('parseCall %s fd: 0x%x cmd: 0x%x arg: 0x%x' % (fun, fd, cmd, arg))
        if fun == 'fopen':
            faddr = frame['param1']
            exit_info.fname = self.mem_utils.readString(self.cpu, faddr, 256)
            if exit_info.fname.startswith('/'):
                new_addr = faddr+1
                self.mem_utils.setRegValue(self.cpu, 'r0', new_addr)
            trace_msg = '%s fname addr: 0x%x fname: %s' % (fun, faddr, exit_info.fname)
            self.openParams(exit_info)

        elif fun == 'bind':
            ss = vxNet.SockStruct(self.cpu, frame['param2'], self.mem_utils, fd=frame['param1'], length=frame['param3'], lgr=self.lgr)
            trace_msg = ('%s %s' % (fun, ss.getString()))
        elif fun == 'fgets':
            addr = frame['param1']
            count = frame['param2']
            fd = frame['param3']
            exit_info.old_fd = fd
            exit_info.count = count
            exit_info.retval_addr = addr
            trace_msg = '%s addr: 0x%x count: 0x%x FD: 0x%x' % (fun, addr, count, fd)
            self.readParams(exit_info, frame)
             
        else:
            frame_string = taskUtils.stringFromFrame(frame)
            trace_msg = ('%s %s' % (fun, frame_string))
        if trace_msg is not None: 
            self.lgr.debug('vxKSyscall parseCall '+trace_msg.strip()) 
            if trace_msg is not None and self.trace_mgr is not None:
                if len(trace_msg.strip()) > 0:
                    self.trace_mgr.write(trace_msg+'\n')
    def clearHackme(self):
        self.hackme = False

    def symbolHap(self, user_param, conf_object, break_num, memory):
        # entered when a global symbol was hit.
        addr = memory.logical_address
        self.lgr.debug('symbolHap addr 0x%x' % addr)
        #ttbr = self.cpu.translation_table_base0
        #cpu = SIM_current_processor()
        reg_num = self.cpu.iface.int_register.get_number('sp')
        sp_value = self.cpu.iface.int_register.read(reg_num)
        cur_task = self.task_utils.getCurrentTask()
        if addr in self.global_sym:
            #print('hit global sym %s at 0x%x' % (self.global_sym[addr], addr))
            # Hack to use stack value to distinguish our thread from other threads
            #if sp_value > 0x78e00000 and sp_value < 0x78f00000:
            #if sp_value > 0x79000000:
            if self.hackme:
                self.lgr.debug('hit global sym %s at 0x%x sp_value: 0x%x cur_task: 0x%x self.cpu: %s cycles: 0x%x' % (self.global_sym[addr], addr, sp_value, cur_task, self.cpu.name, self.cpu.cycles))
            elif True:
                self.lgr.debug('hit global sym %s at 0x%x sp_value: 0x%x cur_task: 0x%x self.cpu: %s cycles: 0x%x' % (self.global_sym[addr], addr, sp_value, cur_task, self.cpu.name, self.cpu.cycles))
                SIM_run_alone(self.disableSyms, None)
                stop_on_exit = False
                #if self.call_list is None:
                #    stop_on_exit = False
                #else:
                #    stop_on_exit = True
                exit_info = ExitInfo(self, stop_on_exit, self.global_sym[addr])
                self.parseCall(self.global_sym[addr], exit_info)
                if self.call_list is None:
                    stop_on_exit = False
                else:
                    stop_on_exit = True
                self.call_exit.setExit(exit_info)
                #if self.global_sym[addr] == 'fopen':
                #    #SIM_break_simulation('fopen')
                #    SIM_run_alone(self.enableSyms, None)
                #    self.hackme = True
                    
                '''
                if self.global_sym[addr] == 'bind':
                    SIM_break_simulation('bind')
                if not self.trace_all:
                    SIM_break_simulation('global')
                '''
            else:
                self.lgr.debug('hit global sym %s at 0x%x sp_value: 0x%x cur_task: 0x%x cpu: %s WRONG STACK?' % (self.global_sym[addr], addr, sp_value, cur_task, self.cpu.name))
                pass
            #if addr == self.fwprintf:
            #    SIM_break_simulation('fwprintf %s' % cpu.name)
        else:
            print('hit other at 0x%x' % (addr))
            self.lgr.debug('hit other at 0x%x conf: %s' % (addr, str(conf_object)))
            SIM_break_simulation('other %s' % self.cpu.name)
        #SIM_break_simulation('hit break')


    def disableSyms(self, dumb=None):
        #self.lgr.debug('disableSysms done')
        self.context_manager.genDisableHap(self.sym_hap)

    def enableSyms(self, dumb=None):
        #self.lgr.debug('enableSyms done')
        self.context_manager.genEnableHap(self.sym_hap)

    def rmAll(self):
        self.disableSyms()
        SIM_run_alone(self.rmModuleHaps, None)
        if self.sym_hap is not None:
            self.context_manager.genDeleteHap(self.sym_hap)
            self.sym_hap = None

    def rmHap(self, hap):
        if hap is not None:
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", hap)

    def addCallParams(self, removed_params):
        return

    def openParams(self, exit_info):
                for call_param in self.call_params:
                    self.lgr.debug('vxKSyscall openParams got param name %s type %s subcall %s' % (call_param.name, type(call_param.match_param), call_param.subcall))
                    if call_param.match_param.__class__.__name__ == 'Dmod':
                         mod = call_param.match_param
                         #self.lgr.debug('is dmod, mod.getMatch is %s' % mod.getMatch())
                         #if mod.fname_addr is None:
                         if mod.getMatch() == exit_info.fname:
                             self.lgr.debug('vxKSyscall openParams , dmod match on fname %s, cell %s' % (exit_info.fname, self.cell_name))
                             exit_info.call_params.append(call_param)
                    elif type(call_param.match_param) is str and (call_param.subcall is None or call_param.subcall.startswith('fopen') and (call_param.proc is None or call_param.proc == self.comm_cache[tid])):
                        if exit_info.fname is None:
                            self.lgr.debug('vxKSyscall openParams open, found potential match_param %s' % call_param.match_param)
                        else:
                            self.lgr.debug('vxKSyscall openParams open, file is %s' % exit_info.fname)
                        if exit_info.fname is None or call_param.match_param in exit_info.fname:
                            self.lgr.debug('vxKSyscall openParams open, found actual match_param %s' % call_param.match_param)
                            exit_info.call_params.append(call_param)
                            exit_info.stop_on_exit = True                    
                        break
                    elif call_param.name == 'runToCall' and exit_info.call_name == call_param.subcall:
                        self.lgr.debug('vxKSyscall openParams open runToCall for fopen')
                        exit_info.call_params.append(call_param)

    def readParams(self, exit_info, frame):
        self.lgr.debug('vxKSyscall readParams num call_params %d' % len(self.call_params))
        for call_param in self.call_params:
            ''' look for matching FD '''
            if type(call_param.match_param) is int:
                self.lgr.debug('vxKSyscall readParams is int, match_param is %s' % (call_param.match_param))
                if call_param.match_param == frame['param3'] and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
                    if call_param.nth is not None:
                        call_param.count = call_param.count + 1
                        self.lgr.debug('vxKSyscall readParams read call_param.nth not none, is %d, count is %d' % (call_param.nth, call_param.count))
                        if call_param.count >= call_param.nth:
                            self.lgr.debug('count >= param, set it')
                            syscall.addParam(exit_info, call_param)
                            if self.kbuffer is not None:
                                self.lgr.debug('vxKSyscall readParams read kbuffer for addr 0x%x' % exit_info.retval_addr)
                                self.kbuffer.read(exit_info.retval_addr, exit_info.count)
                    else:
                        self.lgr.debug('vxKSyscall readParams read, call_param.nth is none, call it matched')
                        syscall.addParam(exit_info, call_param)
                        if self.kbuffer is not None:
                            self.lgr.debug('vxKSyscall readParams read kbuffer for addr 0x%x' % exit_info.retval_addr)
                            self.kbuffer.read(exit_info.retval_addr, exit_info.count)
            elif call_param.match_param.__class__.__name__ == 'Dmod':
                ''' handle read dmod during syscall return '''
                #self.lgr.debug('vxKSyscall readParams read, is dmod: %s' % call_param.match_param.toString())
                if call_param.match_param.tid is not None and (tid != call_param.match_param.tid or exit_info.old_fd != call_param.match_param.fd):
                    #self.lgr.debug('vxKSyscall readParams read, is dmod, but tid or fd does not match, tid:%s match:%s fd:%d  match %d' % (tid, call_param.match_param.tid, exit_info.old_fd, call_param.match_param.fd))
                    continue
                elif call_param.match_param.getComm() is not None and call_param.match_param.getComm() != comm:
                    #self.lgr.debug('vxKSyscall readParams read, is dmod, but comm does not match,  match') 
                    continue
                exit_info.call_params.append(call_param)
            else:
                self.lgr.debug('vxKSyscall readParams unhandled match param type %s' % (type(call_param.match_param)))

    def setModuleBreak(self):
        for module in self.so_map.moduleList():
            if module not in self.module_bp:
                module_info = self.so_map.getModuleInfo(module)
                bp = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, module_info.addr, module_info.size, 0)
                self.module_bp.append(bp)
                hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.moduleHap, None, bp)
                self.module_hap.append(hap)
                self.lgr.debug('vxKSyscall setModule Break set on 0x%x size 0x%x' % (module_info.addr, module_info.size))

    def moduleHap(self, dumb, conf_object, break_num, memory):
        self.lgr.debug('vxKSyscall moduleHap')
        if break_num not in self.module_bp:
            return
        self.lgr.debug('vxKSyscall moduleHap.  set globals')
        SIM_run_alone(self.setGlobal, self.call_list)
        SIM_run_alone(self.rmModuleHaps, None)

    def rmModuleHaps(self, dumb):
        for bp in self.module_bp:
            SIM_delete_breakpoint(bp)
        for hap in self.module_hap:
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", hap)
        self.module_bp = []
        self.module_hap = []

    def hasCallParam(self, param_name):
        retval = False
        for call_param in self.call_params:
            if call_param.name == param_name:
                retval = True
                break 
        return retval
    def rmCallParam(self, call_param, quiet=False):
        self.lgr.debug('sycall rmCallParam syscall %s param %s' % (self.name, call_param.name))
        if call_param in self.call_params: 
            self.call_params.remove(call_param)
        elif not quiet:
            self.lgr.error('sycall rmCallParam, but param does not exist?')

    def rmCallParamName(self, call_param_name):
        return_list = []
        rm_list = []
        for cp in self.call_params:
            if cp.name == call_param_name:
                rm_list.append(cp)
            else:
                return_list.append(cp)
        for cp in rm_list:
            self.call_params.remove(cp)
        return return_list

    def stopTrace(self, immediate=False):
        self.rmAll()

    def stopAlone(self, msg):
        ''' NOTE: this is also called by vxKCallExit '''
        eip = self.top.getEIP()
        if self.stop_action is not None:
            self.stop_action.setExitAddr(eip)
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
            	     self.stopHap, msg)
        self.lgr.debug('vxKSyscall stopAlone cell %s added stopHap %d Now stop. msg: %s' % (self.cell_name, self.stop_hap, msg))
        SIM_break_simulation(msg)

    def stopHap(self, msg, one, exception, error_string):
        '''  Invoked when a vxKSyscall (or more typically its exit back to user space) triggers
             a break in the simulation
        '''
        if self.stop_hap is not None:
            hap = self.stop_hap
            SIM_run_alone(self.rmStopHap, hap)
            self.stop_hap = None
            eip = self.mem_utils.getRegValue(self.cpu, 'pc')
            if self.stop_action is not None:
                self.lgr.debug('vxKSyscall stopHap name: %s cycle: 0x%x eip: 0x%x exception %s error %s linger: %r' % (self.name, self.stop_action.hap_clean.cpu.cycles, eip, str(exception), str(error_string), self.linger))
            else:
                self.lgr.debug('vxKSyscall stopHap, no stop_action') 
            if not self.linger:
                break_list = self.stop_action.getBreaks()
                if eip not in break_list and eip != self.stop_action.getExitAddr():
                    self.lgr.debug('vxKSyscall stopHap 0x%x not in break list, not our stop %s' % (eip, ' '.join(hex(x) for x in break_list)))
                    #self.top.skipAndMail()
                    return
       
                for hc in self.stop_action.hap_clean.hlist:
                    if hc.hap is not None:
                        #self.lgr.debug('will delete hap %s' % str(hc.hap))
                        self.context_manager.genDeleteHap(hc.hap)
                        hc.hap = None
                self.lgr.debug('vxKSyscall stopHap will delete hap %s' % str(self.stop_hap))
                ''' check functions in list '''
                self.lgr.debug('vxKSyscall stopHap call to rmExitHap')
                self.call_exit.rmExitHap(None)

                ''' TBD when would we want to close it?'''
                if self.trace_mgr is not None:
                    self.trace_mgr.flush()
                self.top.idaMessage() 
                ''' Run the stop action, which is a hapCleaner class '''
                self.lgr.debug('vxKSyscall stopHap run stop_action')
                self.stop_action.run(cb_param=msg)

                if self.call_list is not None:
                    for callname in self.call_list:
                        #self.top.rmCallTrace(self.cell_name, callname)
                        self.top.rmCallTrace(self.cell_name, self.name)
            else:
                self.lgr.debug('vxKSyscall will linger and catch next occurance')
                self.top.skipAndMail()

    def rmStopHap(self, hap):
       RES_hap_delete_callback_id("Core_Simulation_Stopped", hap)
