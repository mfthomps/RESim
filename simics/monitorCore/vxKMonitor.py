'''
Experimental VxWorks DKM tracker.
'''
import os
import sys
from simics import *
from resimHaps import *
import decodeArm as decode
import resimUtils
import memUtils
import taskUtils
import vxKMemUtils
import syscall

class VxKMonitor():
    def __init__(self, top, cpu, cell_name, mem_utils, task_utils, so_map, syscall_mgr, context_manager, run_from_snap, comp_dict, lgr):
        
        self.lgr = lgr
        self.cpu = cpu
        self.top = top
        #cpu0_str="zynqmp.soc.rpu.cores[0]"
        #cpu1_str="zynqmp.soc.rpu.cores[1]"
        #self.cpu0 = SIM_get_object(cpu0_str)
        #self.cpu1 = SIM_get_object(cpu1_str)
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.context_manager = context_manager
        self.so_map = so_map
        self.syscall_mgr = syscall_mgr
        self.sym_hap = None
        self.cur_task_hap = None
        self.stop_hap = None

        
        # values for myCMakeDKM.out
        #self.module_addr = 0x786bb5b8
        #self.module_size = 1094

        # values for pltdkm_custom.out
        #self.module_addr = 0x79666208
        #self.module_size = 855614
        self.module_hap = {}
        self.stop_in_module = False

        self.hack_syscall = None

        # tbd tie this to some debug call
        self.debug_module = comp_dict['MODULE']

        self.not_mapped_hap = SIM_hap_add_callback_index("Core_Address_Not_Mapped", self.notMapped, None, 0)
        undefined_instruction = 5
        #self.fault_hap1 = RES_hap_add_callback_obj_range("Core_Exception", self.cpu, 0,
        #         self.faultCallback, self.cpu, 0, 13) 
        self.fault_hap1 = RES_hap_add_callback_obj_index("Core_Exception", self.cpu, 0,
                 self.faultCallback, self.cpu, undefined_instruction) 

        self.top.loadJumpers()

    def faultCallback(self, cpu, one, exception_number):
        self.lgr.error('fault callback %d' % exception_number)
        SIM_break_simulation('fault callback')

    def notMapped(self, dumb, conf_obj, addr, access_type, size):
        if self.not_mapped_hap is None:
            return
        msg = 'not mapped: 0x%x' % addr
        SIM_break_simulation(msg)
        hap = self.not_mapped_hap
        SIM_run_alone(self.rmMapHap, hap)
        self.not_mapped_hap = None

    def rmMapHap(self, hap):
        if hap is not None:
            SIM_hap_delete_callback_id("Core_Address_Not_Mapped", hap)

    def dbg(self):
        cmd = 'new-gdb-remote cpu=%s architecture=arm port=9123' % (self.cpu.name)
        SIM_run_command(cmd)

    def getPC(self, cpu):
        reg_num = cpu.iface.int_register.get_number('pc')
        reg_value = cpu.iface.int_register.read(reg_num)
        return reg_value


    def runTo(self, fun):
        got_fun = None
        for addr in self.global_sym:
            if self.global_sym[addr] == fun:
                got_fun = addr
                break
        if got_fun is not None:
            bp = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, got_fun, 1, 0)
            self.global_sym_break[got_fun] = bp
            self.sym_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.symbolHap, None, bp)
            self.lgr.debug('runTo set hap for fun %s at addr 0x%x' % (fun, got_fun))
        else:
            self.lgr.error('runTo failed to find %s in global symbols' % fun)
 
    def so(self):
        pc = self.getPC(self.cpu)
        next_instruct = pc + 4
        bp = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, next_instruct, 1, 0)
        self.stop_hap = self.top.RES_add_stop_callback(self.stopHap, bp)
        SIM_continue(0)

    def stopHap(self, bp, one, exception, error_string):
        if self.stop_hap is not None: 
            self.lgr.debug('stopHap bp %d' % bp)
            SIM_delete_breakpoint(bp)                        
            hap = self.stop_hap
            SIM_run_alone(self.rmStopHap, hap)
            self.stop_hap = None
            print('stopped')

    def rmStopHap(self, hap):
        if hap is not None:
            self.top.RES_delete_stop_hap(hap)

    def disassemble(self, count=1):
        pc = self.getPC(self.cpu)
        for i in range(count):
            instruct = SIM_disassemble_address(self.cpu, pc, 1, 0)
            self.lgr.debug('disassemble pc 0x%x instruct %s' % (pc, instruct[1]))
            if instruct[1].startswith('bl'):
                parts = instruct[1].split()
                dest = None
                if len(parts) == 2:
                    try:
                        dest = int(parts[1], 16)
                    except:
                        pass
                if dest is not None:
                    self.lgr.debug('disassemble dest is 0x%x' % dest)
                    if dest in self.global_sym:
                        print('bl %s' % self.global_sym[dest])
                    else:
                        dest = None
                if dest is None:
                    print(instruct[1])
            else:
                print(instruct[1])
            pc = pc + 4

    def traceAll(self, record_fd=None):
        self.lgr.debug('traceAll')
        context = self.cpu.current_context
        self.syscall_mgr.watchAllSyscalls(context, 'traceAll', trace=True)


        '''
        self.trace_all = True
        if self.so_map.inModule(self.debug_module):
            self.lgr.debug('traceAll in app, set globals')
            self.setGlobal()
        else:
            self.lgr.debug('traceAll not in app, set module break')
            self.setModuleBreak()
        '''

    def origOffset(self):
        pc = self.getPC(self.cpu)
        file, start, end = self.so_map.getSOInfo(pc)
        ida = pc - start
        print('Orig address: 0x%x' % ida)


    def toModule(self):
        if self.so_map.inModule(self.debug_module):
            print('Already in module %s' % self.debug_module)
        else:
            self.setModuleBreak()
            self.stop_in_module = True
            SIM_continue(0)

    def setModuleBreak(self):
        for module in self.so_map.moduleList():
            if module not in self.module_hap:
                module_info = self.so_map.getModuleInfo(module)
                bp = self.context_manager.genBreakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, module_info.addr, module_info.size, 0)
                hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.moduleHap, None, bp, 'syscall')
                self.module_hap[module] = hap
                self.lgr.debug('vxKCallExit setExit set on 0x%x size 0x%x context %s' % (module_info.addr, module_info.size, str(self.cpu.current_context)))

    def moduleHap(self, dumb, conf_object, break_num, memory):
        self.lgr.debug('vxKMonitor moduleHap')
        for module in self.module_hap:
            self.context_manager.genDeleteHap(self.module_hap[module])
        self.module_hap = {}    
        SIM_break_simulation('In module ?')

    def watchHack(self):
        self.hack_syscall = self.syscall_mgr.watchSyscall(None, ['printf', 'bind', 'listen', 'select'], [], 'watchHack')

    def runToIO(self, fd, linger, break_simulation, count, flist_in, origin_reset, run_fun, proc, run, kbuf, call_list, sub_match=None, just_input=False):

        call_params = syscall.CallParams('runToIO', None, fd, break_simulation=break_simulation, proc=proc, sub_match=sub_match)        
        ''' nth occurance of syscalls that match params '''
        call_params.nth = count
       
        if True:
            self.lgr.debug('runToIO on FD %s' % str(fd))

            if True:
                skip_and_mail = True
                if flist_in is not None:
                    ''' Given callback functions, use those instead of skip_and_mail '''
                    skip_and_mail = False
                self.lgr.debug('vxKMonitor runToIO, add new syscall')
                kbuffer_mod = None
                # TBD move kbuf set to syscallManager?
                #if kbuf is not None:
                #    kbuffer_mod = kbuf
                #    self.sharedSyscall.setKbuffer(kbuffer_mod)
                if call_list is None:
                    if just_input:
                        calls = ['fgets', 'fgetc', 'fscanf', 'read', 'recv']
                    else:
                        # TBD fix this
                        calls = ['BIND', 'CONNECT', 'RECV', 'SEND', 'RECV_DATAGRAM', 'SEND_DATAGRAM', 'ReadFile', 'WriteFile', 'QueryValueKey', 'EnumerateValueKey', 'Close', 'GET_PEER_NAME']
                else:
                    calls = call_list
                the_syscall = self.syscall_mgr.watchSyscall(None, calls, [call_params], 'runToIO', linger=linger, flist=flist_in, 
                                 skip_and_mail=skip_and_mail, kbuffer=kbuffer_mod)
                ''' find processes that are in the kernel on IO calls '''
                '''
                frames = self.getDbgFrames()
                skip_calls = []
                for tid in list(frames):
                    if frames[tid] is None:
                        self.lgr.error('frames[%s] is None' % tid)
                        continue
                    call = self.task_utils.syscallName(frames[tid]['syscall_num'], False) 
                    self.lgr.debug('vxKMonitor runToIO found %s in kernel for pid:%s' % (call, tid))
                    if call != 'DeviceIoControlFile' and (call not in calls or call in skip_calls):
                       del frames[tid]
                       self.lgr.debug('vxKMonitor runToIO removed %s in kernel for tid:%s' % (call, tid))
                    else:
                       self.lgr.debug('vxKMonitor runToIO kept frames for tid %s' % tid)
                if len(frames) > 0:
                    self.lgr.debug('wnMonitor runToIO, call to setExits')
                    the_syscall.setExits(frames, origin_reset=origin_reset, context_override=self.context_manager.getRESimContext()) 
                #self.copyCallParams(the_syscall)
                '''
    
    
            if run_fun is not None:
                SIM_run_alone(run_fun, None) 
            if run:
                self.lgr.debug('runToIO now run')
                SIM_continue(0)
#track = Track()

