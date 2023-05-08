from simics import *
import os
import json
import struct
import binascii
'''
Functions for experimenting with Win7 
to determine how parameters are passed to the kernel.
These assume a param has been built containing the pid offset.
And it assumes the param includes the syscall_jump value
reflecting jump table values for syscalls.
The physical address of the current task record is passed in,
e.g., from getKernelParam.  A real system would compute that from
the param, using gs_base and logic to account for aslr.

'''
watch_stack_params = 6
class Win7CallParams():
    def __init__(self, cpu, cell, cell_name, mem_utils, current_task_phys, param, lgr, stop_on=None, only=None):
        self.lgr = lgr
        self.param = param
        
        #self.current_task_phys = 0x3634188
        self.current_task_phys = current_task_phys
        self.entry = param.sysenter
        #self.entry = 0xfffff80003622bc0
        self.lgr.debug('Win7CallParams current task phys 0x%x sysenter 0x%x' % (self.current_task_phys, self.entry))
        self.entry_break = None
        self.entry_hap = None
        self.exit_break = None
        self.exit_hap = None
        self.only = only
       
        self.user_break = None
        self.user_hap = None

        ''' break/hap to collect parameters by pid '''
        self.stack_param_break = {}
        self.stack_param_hap = {}
        self.open_file_break = {}
        self.open_file_hap = {}
        self.open_file_break2 = {}
        self.open_file_hap2 = {}
        self.current_call = {}
        self.current_call_params = {}
        self.entry_rsp = {}
        self.all_reg_values = {}
        self.mem_utils = mem_utils
        self.cell = cell
        self.cell_name = cell_name
        self.cpu = cpu
        self.stop_on = stop_on
        resim_dir = os.getenv('RESIM_DIR')
        self.call_map = {}
        self.call_num_map = {}
        w7mapfile = os.path.join(resim_dir, 'windows', 'win7.json')
        if os.path.isfile(w7mapfile):
            cm = json.load(open(w7mapfile))     
            for call in cm:
                self.call_map[int(call)] = cm[call] 
                ''' drop Nt prefix'''
                self.call_num_map[cm[call][2:]] = int(call)
        else:
            self.lgr.error('Cannot open %s' % w7mapfile)
            return
        ''' track parameters to different calls '''
        self.call_param_offsets = {}


        context = 'RESim_%s' % self.cell_name
        cmd = 'new-context %s' % context
        self.lgr.debug('cmd is %s' % cmd)
        SIM_run_command(cmd)
        obj = SIM_get_object(context)
        self.resim_context = obj
        self.lgr.debug('context_manager cell %s resim_context defined as obj %s' % (self.cell_name, str(obj)))
        self.default_context = self.cpu.current_context
      
        if only is not None:
            if only in self.call_num_map:
                call_num = self.call_num_map[only]
                self.one_entry = self.getComputed(call_num)
            else:
                self.lgr.error('%s not found in syscall map' % only)
                print('%s' % str(self.call_num_map))
                return
        self.doBreaks()

    def doBreaks(self):
        ''' set breaks on syscall entries and exits '''
        if self.one_entry is not None:
            self.entry_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.one_entry, 1, 0)
            self.entry_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.oneCallHap, None, self.entry_break)
        else:
            self.entry_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sysenter, 1, 0)
            self.entry_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.syscallHap, None, self.entry_break)
            self.exit_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sysret64, 1, 0)
            self.exit_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.exitHap, None, self.exit_break)

    def getComputed(self, callnum):
        ''' given a call number, compute the address of the kernel code that handles the call
            based on observations made walking the instructions that follow syscall entry.''' 
        # looks like  cs:0xfffff800034f1e1d p:0x0034f1e1d  movsx r11,dword ptr [r10+rax*4]
        #             cs:0xfffff800034f1e24 p:0x0034f1e24  sar r11,4
        #             cs:0xfffff800034f1e28 p:0x0034f1e28  add r10,r11
        #                                          ....    call r10
        # syscall_jump is the r10 value.  TBD, this may change based on different call tables, e.g., 
        # windows has separate gui calls?  
        val = callnum * 4 + self.param.syscall_jump
        val = self.mem_utils.getUnsigned(val)
        val = val 
        self.lgr.debug('getComputed syscall_jump 0x%x  val 0x%x' % (self.param.syscall_jump, val))
        entry = self.mem_utils.readPtr(self.cpu, val)
        entry = entry & 0xffffffff
        entry_shifted = entry >> 4
        computed = self.param.syscall_jump + entry_shifted
        self.lgr.debug('getComputed call 0x%x val 0x%x entry 0x%x entry_shifted 0x%x computed 0x%x' % (callnum, val, entry, entry_shifted, computed))
        return computed

    def getCurPid(self):
        pid = None
        comm = None
        cur_thread = SIM_read_phys_memory(self.cpu, self.current_task_phys, self.mem_utils.WORD_SIZE)
        if cur_thread is not None:
            cur_proc = self.mem_utils.readPtr(self.cpu, cur_thread+self.param.proc_ptr)
            if cur_proc is not None:
                pid_ptr = cur_proc + self.param.ts_pid
                pid = self.mem_utils.readWord(self.cpu, pid_ptr)
                if pid is not None:
                    #self.lgr.debug('getCurPid cur_proc, 0x%x pid_offset %d pid_ptr 0x%x pid %d' % (cur_proc, self.param.ts_pid, pid_ptr, pid))
                    comm = self.mem_utils.readString(self.cpu, cur_proc+self.param.ts_comm, 16)
            else:
                self.lgr.debug('getCurPid cur_proc is None reading cur_thread 0x%x' % cur_thread)
        else:
            self.lgr.debug('getCurPid cur_thread is None')
        return cur_proc, pid, comm
 
    def parseOpen(self, rsp, pid):
        ''' not used '''
        retval = ''
        offset = 40
        msg = 'OpenFile pid:%d ' % pid
        params = []
        for i in range(4):
            offset = 40 + i*8
            sp_off = rsp + offset 
            value = self.mem_utils.readWord(self.cpu, sp_off)
            params.append(value)
            add = 'offset_%d  value: 0x%x' % (offset, value) 
            msg = msg + add + ' '
        if params[0] == 3:
            fname_off = rsp + 64
            fname_ptr = self.mem_utils.readPtr(self.cpu, fname_off)
            if fname_ptr is not None:
                barray = self.mem_utils.readBytes(self.cpu, fname_ptr, 80)
                if barray is not None:
                    stuff = barray.decode('utf-16le', errors='replace')
                    msg = msg + '\n\t ' + stuff
        return msg

    def oneCallHap(self, dumb, third, forth, memory):
        cur_task, pid, comm = self.getCurPid()
        self.lgr.debug('oneCallHap only: %s pid:%d (%s)' % (self.only, pid, comm))

        gs_base = self.cpu.ia32_gs_base
        ptr2stack = gs_base+0x6008
        stack_val = self.mem_utils.readPtr(self.cpu, ptr2stack)
        user_stack = self.mem_utils.readPtr(self.cpu, stack_val-16)
        rcx = self.mem_utils.readPtr(self.cpu, stack_val-40)
        rdx = self.mem_utils.getRegValue(self.cpu, 'rdx')
        r8 = self.mem_utils.getRegValue(self.cpu, 'r8')
        r9 = self.mem_utils.getRegValue(self.cpu, 'r9')
        self.lgr.debug('oneCallHap ptr2stack 0x%x stack_val 0x%x user_stack 0x%x, rcx: 0x%x rdx: 0x%x, r8:0x%x, r9:0x%x' % (ptr2stack, stack_val, 
              user_stack, rcx, rdx, r8, r9))
        #SIM_break_simulation('onecall userstack 0x%x' % user_stack)
        self.cpu.current_context = self.resim_context
        self.exit_break = SIM_breakpoint(self.resim_context, Sim_Break_Linear, Sim_Access_Execute, self.param.sysret64, 1, 0)
        self.exit_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.exitOneHap, None, self.exit_break)

        self.user_break = SIM_breakpoint(self.resim_context, Sim_Break_Linear, Sim_Access_Read, 0, (self.param.kernel_base-1),  0)
        self.user_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.userReadHap, None, self.user_break)

    def syscallHap(self, dumb, third, forth, memory):
        ''' hit when kernel is entered due to sysenter '''
        #self.lgr.debug('sycallHap')
        cur_task, pid, comm = self.getCurPid()
        #SIM_break_simulation(pid)
        #return
        #if pid is None:
        #    print('oh no')
        #    return
        if cur_task is not None:
            rax = self.mem_utils.getRegValue(self.cpu, 'rax')
            ''' Use the call map to get the call name, and strip off "nt" '''
            if rax in self.call_map:
                call_name = self.call_map[rax][2:]

                if call_name == 'RaiseException':
                    ''' This will just bounce to a user space exception handler.
                        Do not track or confusion will reign. '''
                    self.lgr.debug('syscallHap got RaiseException, just return')
                    return

                #if not self.got_one and call_name != 'OpenFile':
                #    #self.lgr.debug('syscallHap looking for Open got %s' % call_name)
                #    return
                #self.got_one = True
                if pid is not None:
                    if pid in self.stack_param_hap:
                        self.lgr.error('syscallHap pid:%d still has entry in stack_param_hap.  Fix this race!' % pid)
                    #entry = self.getComputed(rax)     
                    self.current_call_params[pid] = {}
                    self.current_call[pid] = rax
                    rsp = self.mem_utils.getRegValue(self.cpu, 'rsp')
                    self.entry_rsp[pid] = rsp
                    self.lgr.debug('syscallHap cur_task 0x%x pid:%d (%s) rsp: 0x%x rax: %d call: %s' % (cur_task, pid, comm, rsp, rax, call_name)) 
                    #if call_name == 'OpenFile':
                    #    msg = self.parseOpen(rsp, pid)
                    #    self.lgr.debug(msg)
                    if call_name == self.stop_on:
                        SIM_break_simulation('syscall stop on call')

                    if call_name == 'OpenFile':
                        SIM_break_simulation('is open')
                        entry = self.getComputed(rax)     
                        self.lgr.debug('computed entry would be 0x%x' % entry)

                    if rax not in self.call_param_offsets:
                        self.call_param_offsets[rax] = []
                    self.watchStackParams(pid, call_name)
                    self.all_reg_values[pid] = self.allRegValues()
                else:
                    self.lgr.debug('got none for pid task 0x%x' % cur_task)
            elif pid is not None:
                self.lgr.debug('call number %d not in call map, pid:%d' % (rax, pid))
            else:
                self.lgr.debug('got none for pid and no bad call num %d for task 0x%x' % (rax, cur_task))

    def allRegValues(self):
        msg = ''
        for reg in self.mem_utils.ia64_regs:
            value = self.mem_utils.getRegValue(self.cpu, reg)
            msg_add = '%s: 0x%x ' % (reg, value)
            msg = msg+msg_add
        return msg
 
    def recordOpen(self, pid):
        ''' gather values of what might be parameters to the open syscall'''
        retval = ''
        msg = 'return from OpenFile pid:%d rsp: 0x%x ' % (pid, self.entry_rsp[pid])
        for offset in self.current_call_params[pid]:
            if self.current_call_params[pid][offset] is not None:
                orig_bytes = self.current_call_params[pid][offset]
                #orig_bytes.reverse()
                hexstring = binascii.hexlify(orig_bytes)
                msg_add = ' offset 0x%x (%d) value 0x%x' % (offset, offset, int(hexstring,16))
            else:
                msg_add = ' offset 0x%x (%d) value is None' % (offset, offset)
            msg = msg + ' '+msg_add
        offset_list = [64, 72]
        for offset in offset_list:
            if offset in self.current_call_params[pid] and self.current_call_params[pid][offset] is not None:
                orig_bytes = self.current_call_params[pid][offset]
                orig_bytes.reverse()
                param_ptr = None
                fname_maybe = ''
                if len(orig_bytes) == 8:
                    param_ptr = struct.unpack("<Q", orig_bytes)[0]
                elif len(orig_bytes) == 4:
                    param_ptr = struct.unpack("<L", orig_bytes)[0]
                else:
                    self.lgr.debug('offset %d len of orig_bytes is %d, does not look like a pointer?' % (offset, len(orig_bytes)))
                    fname_maybe = 'Kernel only read %d bytes from offset %d of what should be an address' % (len(orig_bytes), offset)
                if param_ptr is not None:
                    self.lgr.debug('recordOpen offset %d param_ptr 0x%x' % (offset, param_ptr))
                    barray = self.mem_utils.readBytes(self.cpu, param_ptr, 80)
                    if len(barray) == 0:
                        fname_maybe = 'offset %d Address 0x%x not mapped' % (offset, param_ptr) 
                    else:
                        fname_maybe = 'offset %d: %s' % (offset, barray.decode('utf-16le', errors='replace'))
                        #string = 'offset %d %s' % (offset, self.mem_utils.readString(self.cpu, param_ptr, 80))
                msg = msg + '\n\t ' + fname_maybe
        msg = msg + '\n'+self.all_reg_values[pid]
        return msg

    class DelRec():
        def __init__(self, break_num, hap, pid):
            self.break_num = break_num
            self.hap = hap
            self.pid = pid

    def exitOneHap(self, dumb, third, forth, memory):
        if self.exit_hap is not None:
            self.lgr.debug('exitOneHap, return to default context and remove exit hap')
            SIM_run_alone(self.stopWatchExit, self.exit_hap)
            self.exit_hap = None
        if self.user_hap is not None:
            SIM_run_alone(self.rmUserHap, self.user_hap)
            self.user_hap = None

    def rmUserHap(self, user_hap):
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", user_hap)
        if self.user_break is not None:
            SIM_delete_breakpoint(self.user_break)
            self.user_break = None

     
 
    def exitHap(self, dumb, third, forth, memory):
        ''' hit when kernel is about to exit back to user space via sysret64 '''
        #self.lgr.debug('exitHap')
        if self.exit_hap is None:
            return
        cur_task, pid, comm = self.getCurPid()
        call_name = None
        if pid is None:
            return
        if cur_task is not None:
            rax = self.mem_utils.getRegValue(self.cpu, 'rax')
            if pid is not None:
                self.lgr.debug('exitHap cur_task: 0x%x pid:%d (%s) rax: 0x%x' % (cur_task, pid, comm, rax))
            else:
                self.lgr.debug('exitHap PID is none for cur_task: 0x%x' % (cur_task))
            if pid in self.all_reg_values:
                self.lgr.debug(self.all_reg_values[pid])
            if pid in self.stack_param_hap:
                del_rec = self.DelRec(self.stack_param_break[pid], self.stack_param_hap[pid], pid)
                del self.stack_param_hap[pid]
                del self.stack_param_break[pid]
                ''' Cannot delete HAPS from main Simics thread, must "run alone" '''
                SIM_run_alone(self.stopWatchStack, del_rec)
 
            if pid in self.current_call and self.current_call[pid] in self.call_map:
                call_name = self.call_map[self.current_call[pid]][2:]
                #self.lgr.debug('exitHap callname %s' % call_name)
                if call_name == 'OpenFile':
                    msg = self.recordOpen(pid)
                    self.lgr.debug(msg)
                    #if 'not mapped' in msg:
                    #    SIM_break_simulation('not mapped')
            if self.stop_on is not None:
                #self.lgr.debug('exitHap stopon is %s and pid' % self.stop_on)
                if call_name is not None:
                    if call_name == self.stop_on:
                        SIM_break_simulation('exitHap stop on call')

    def watchStackParams(self, pid, call_name):
        ''' Set a break on 80 bytes starting at the user-space sp to record kernel references to the
            user space stack '''
        rsp = self.mem_utils.getRegValue(self.cpu, 'rsp')
        self.lgr.debug('watchStackParams set break on sp 0x%x' % rsp)
        stack_param_start = rsp+40
        stack_param_bytes = watch_stack_params * 8
        self.stack_param_break[pid] = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Read, stack_param_start, stack_param_bytes, 0)
        self.stack_param_hap[pid] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.stackParamHap, call_name, self.stack_param_break[pid])

    def stopWatchExit(self, exit_hap):
        self.cpu.current_context = self.default_context
        self.lgr.debug('stopWatchExit cpu reset to %s'  % str(self.cpu.current_context))
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", exit_hap)
        if self.exit_break is not None:
            SIM_delete_breakpoint(self.exit_break)
            self.exit_break = None

    def stopWatchStack(self, del_rec):
        ''' Stop watching stack references, e.g., because we are exiting the kernel '''
        ''' the self.stack_param_hap and break were removed in the main thread to avoid a race '''
        self.lgr.debug('stopWatchStack')
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", del_rec.hap)
        SIM_delete_breakpoint(del_rec.break_num)
        if del_rec.pid in self.open_file_break:
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.open_file_hap[del_rec.pid])
            SIM_delete_breakpoint(self.open_file_break[del_rec.pid])
            del self.open_file_hap[del_rec.pid]
            del self.open_file_break[del_rec.pid]
        if del_rec.pid in self.open_file_break2:
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.open_file_hap2[del_rec.pid])
            SIM_delete_breakpoint(self.open_file_break2[del_rec.pid])
            del self.open_file_hap2[del_rec.pid]
            del self.open_file_break2[del_rec.pid]
 
    class PidAddr():
        def __init__(self, pid, addr):
            self.pid = pid
            self.addr = addr

    def stackParamHap(self, call_name, third, forth, memory):
        ''' Hit when kernel reads values in user space stack, implying they are parameters. '''
        ''' me thinks there are race conditions here '''
        #self.lgr.debug('stackParamHap') 
        cur_task, pid, comm = self.getCurPid()
        if pid in self.stack_param_hap:
            addr = memory.logical_address
            offset = addr - self.entry_rsp[pid] 
            rip = self.mem_utils.getRegValue(self.cpu, 'rip')
            orig_value = self.mem_utils.readBytes(self.cpu, addr, memory.size)
            if orig_value is not None:
                value = orig_value
                value.reverse()
                hexstring = binascii.hexlify(value)
                self.lgr.debug('stackParamHap pid:%d (%s) rip: 0x%x read value 0x%s from 0x%x, offset 0x%x (%d) from sp 0x%x cycles:0x%x' % (pid, comm, rip, hexstring, addr, offset, offset, self.entry_rsp[pid], self.cpu.cycles))
                if call_name == 'OpenFile': 
                    pid_addr = self.PidAddr(pid, addr)
                    if offset == 64:
                        SIM_run_alone(self.watchOpenFilePtr, pid_addr)
                    elif offset == 72:
                        SIM_run_alone(self.watchOpenFilePtr2, pid_addr)
            else:
                self.lgr.debug('stackParamHap pid:%d rip: 0x%x could not read value from 0x%x, offset %d from sp 0x%x' % (pid, rip, addr, offset, self.entry_rsp[pid]))
            ''' for every pid and every call '''
            if offset not in self.current_call_params[pid]:
                self.current_call_params[pid][offset] = orig_value
            else:
                self.lgr.debug('offset %d already in current_call_params for pid %d' % (offset, pid))

            ''' record once for reference'''
            if offset not in self.call_param_offsets[self.current_call[pid]]:
                self.call_param_offsets[self.current_call[pid]].append(offset) 

    def watchOpenFilePtr(self, pid_addr):
        ''' set a break/hap on reads of file names? '''
        if pid_addr.pid not in self.open_file_break:
            file_ptr = self.mem_utils.readPtr(self.cpu, pid_addr.addr)
            if file_ptr is not None and file_ptr != 0:
                self.lgr.debug('watchOpenFilePtr for pid:%d addr: 0x%x file_ptr: 0x%x' % (pid_addr.pid, pid_addr.addr, file_ptr))
                self.open_file_break[pid_addr.pid] = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Read, file_ptr, 8, 0)
                self.open_file_hap[pid_addr.pid] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.openFilePtr, pid_addr.pid, self.open_file_break[pid_addr.pid])

    def watchOpenFilePtr2(self, pid_addr):
        ''' set a break/hap on reads of file names from offset 72 '''
        if pid_addr.pid not in self.open_file_break2:
            file_ptr = self.mem_utils.readPtr(self.cpu, pid_addr.addr)
            if file_ptr is not None and file_ptr != 0:
                self.lgr.debug('watchOpenFilePtr2 for pid:%d addr: 0x%x file_ptr: 0x%x' % (pid_addr.pid, pid_addr.addr, file_ptr))
                self.open_file_break2[pid_addr.pid] = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Read, file_ptr, 8, 0)
                self.open_file_hap2[pid_addr.pid] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.openFilePtr2, pid_addr.pid, self.open_file_break2[pid_addr.pid])

    def showParams(self):
        ''' dump the collected parameter offsets for each syscall '''
        jd = json.dumps(self.call_param_offsets, indent=4)
        with open('syscall_params.json', 'w') as fh:
            fh.write(jd)
        for call_num in self.call_param_offsets:
            call_name = self.call_map[call_num][2:]
            print('%s' % call_name)
            for offset in sorted(self.call_param_offsets[call_num]):
                print('\t%d' % offset) 

    def openFilePtr(self, pid, third, forth, memory):
        ''' Hit when file name pointers are read '''
        if pid in self.open_file_break:
            rip = self.mem_utils.getRegValue(self.cpu, 'rip')
            self.lgr.debug('openFilePtr FILE READ pid:%d  rip: 0x%x addr: 0x%x' % (pid, rip, memory.logical_address))

    def openFilePtr2(self, pid, third, forth, memory):
        if pid in self.open_file_break2:
            rip = self.mem_utils.getRegValue(self.cpu, 'rip')
            self.lgr.debug('openFilePtr2 FILE READ pid:%d  rip: 0x%x addr: 0x%x' % (pid, rip, memory.logical_address))

    def userReadHap(self, call_name, third, forth, memory):
        cur_task, pid, comm = self.getCurPid()
        #self.lgr.debug('userReadHap memory 0x%x len %d' % (memory.logical_address, memory.size))
        orig_value = self.mem_utils.readBytes(self.cpu, memory.logical_address, memory.size)
        if orig_value is not None:
            value = orig_value
            value.reverse()
            hexstring = binascii.hexlify(value)
            self.lgr.debug('userReadHap pid:%d (%s) read value 0x%s from 0x%x, cycles:0x%x' % (pid, comm, hexstring, 
                  memory.logical_address, self.cpu.cycles))

