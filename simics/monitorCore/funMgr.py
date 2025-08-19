'''
 * This software was created by United States Government employees
 * and may not be copyrighted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
'''
import idaFuns
import userIterators
import elfText
import resimUtils
import winProg
import os
import json
import decode
import decodeArm
import decodePPC32
import clibFuns
from simics import *
class FunMgr():
    def __init__(self, top, cpu, cell_name, mem_utils, task_utils, lgr):
        self.relocate_funs = {}
        self.export_funs = {}
        self.ida_funs = {}
        self.cpu = cpu
        self.cell_name = cell_name
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.top = top
        self.lgr = lgr
        self.so_checked = {}
        self.fun_break = {}
        self.user_iterators = {}
        if cpu.architecture.startswith('arm'):
            self.callmn = 'bl'
            self.jmpmn = 'bx'
            self.decode = decodeArm
        elif cpu.architecture == 'ppc32':
            self.callmn = 'bl'
            self.jmpmn = 'b'
            self.decode = decodePPC32
        else:
            self.callmn = 'call'
            self.jmpmn = 'jmp'
            self.decode = decode
        self.trace_addrs = []
        # ARM64 BLR mapping (see ida/resimUtils imports)
        self.call_reg_funs = {}

    def getComm(self, comm_in=None):
        ''' return a comm if idaFuns has this comm, or one that matches it per comm renaming '''
        retval = None
        if comm_in is None:
            comm = self.top.getComm(target=self.cell_name)
        else: 
            comm = comm_in
        if comm in self.ida_funs:
            retval = comm
        else:
            for my_comm in self.ida_funs:
                if self.task_utils.commMatch(comm, my_comm):
                    retval = my_comm
                    break
        return retval

    def getFun(self, addr):
        comm = self.getComm()
        if comm in self.ida_funs:
            ''' Returns the loaded function address of the fuction containing a given ip '''
            return self.ida_funs[comm].getFun(addr)
        else:
            self.lgr.error('funMgr getFun no funs for comm %s. comms for:' % comm)
            for my_comm in self.ida_funs:
                self.lgr.error('\t %s' % my_comm)
            return None

    def getName(self, addr):
        comm = self.getComm()
        if comm in self.ida_funs:
            return self.ida_funs[comm].getName(addr)
        else:
            return None

    def demangle(self, fun):
        comm = self.getComm()
        if comm in self.ida_funs:
            return self.ida_funs[comm].demangle(fun)
        else:
            return None

    def isFun(self, fun):
        ''' given fun value may reflect random load base address '''
        comm = self.getComm()
        retval = False
        if comm in self.ida_funs:
            if self.ida_funs[comm].isFun(fun):
                retval = True
            elif fun in self.relocate_funs[comm]:
                retval = True
        return retval
 
    ''' TBD extend linux soMap to pass load addr '''
    def add(self, path, start, offset=0, text_offset=0):
        comm = self.getComm()
        self.lgr.debug('funMgr add path %s' % path)
        if path is None:
            self.lgr.debug('funMgr add called with path of None')
        elif comm in self.ida_funs:
            use_offset = start
            if offset != 0:
                use_offset = offset - text_offset
            self.ida_funs[comm].add(path, use_offset)
            if offset is not None:
                self.lgr.debug('funMgr add call setRelocate funs path %s offset 0x%x   start 0x%x ' % (path, use_offset, start))
            else:
                self.lgr.debug('funMgr add call setRelocate funs path %s  start 0x%x offset was None' % (path, start))
            
            self.setRelocateFuns(path, offset=use_offset)
            self.setArmBLR(path, offset=use_offset)
            self.loadExports(path)
        else:
            self.lgr.debug('funMgr add called with no IDA funs defined')
            

    def isCall(self, instruct):
        if instruct.startswith(self.callmn):
            return True
        else:
            return False

    def inFun(self, prev_ip, call_to, call_ip=None):
        retval = False
        comm = self.getComm()
        if comm in self.ida_funs: 
            retval = self.ida_funs[comm].inFun(prev_ip, call_to)
            if not retval and call_ip is not None:
                prev_ip_name = clibFuns.adjustFunName(self.ida_funs[comm].getFunName(prev_ip), self, self.lgr)
                call_to_name = clibFuns.adjustFunName(self.ida_funs[comm].getFunName(call_to), self, self.lgr)
                call_ip_name = clibFuns.adjustFunName(self.ida_funs[comm].getFunName(call_ip), self, self.lgr)
                #self.lgr.debug('funMgr inFun prev_ip_name %s call_to_name %s call_ip_name %s' % (prev_ip_name, call_to_name, call_ip_name))
                if prev_ip_name == call_to_name:
                    retval = True
                elif call_to_name == call_ip_name:
                   f1 = self.top.getSOFile(prev_ip) 
                   f2 = self.top.getSOFile(call_to) 
                   f_from = self.top.getSOFile(call_ip)
                   if f1 == f2 and f_from == f1:
                       #self.lgr.debug('funMgr inFun NOT IN function, but call_to fun name matches call_fun name (modulo parameter aliases) and all funs in same so, call it good')
                       retval = True
                else:
                   ''' hack it ok if prev_ip and call_to are in same so file and is called from outside the so '''
                   self.lgr.debug('funMgr inFun prev_ip 0x%x call_to 0x%x, not in fun' % (prev_ip, call_to))
                   f1 = self.top.getSOFile(prev_ip) 
                   f2 = self.top.getSOFile(call_to) 
                   f_from = self.top.getSOFile(call_ip)
                   if f1 == f2 and f_from != f1:
                       #self.lgr.debug('funMgr inFun NOT IN function, but in same SO and call from elsewhere.  call it good?')
                       retval = True
                   elif self.cpu.architecture == 'ppc32':
                       prev_ip_fun_addr = self.getFun(prev_ip)
                       ip = call_to
                       for i in range(50):
                           instruct = SIM_disassemble_address(self.cpu, ip, 1, 0)
                           if instruct[1].startswith('blr'):
                               break
                           if instruct[1].startswith('b '):
                               try:
                                   addr = int(instruct[1].split()[1], 16)
                               except:
                                   break
                               if addr == prev_ip_fun_addr:
                                   retval = True
                                   self.lgr.debug('funMgr inFun ppc fu b to function')
                                   break 
                           ip = ip + instruct[0]
                           
          
        return retval

    def funFromAddr(self, addr):
        comm = self.getComm()
        fun = None
        if addr is not None:
            if comm in self.relocate_funs and addr in self.relocate_funs[comm]:
                #self.lgr.debug('funMgr funFromAddr 0x%x in relocate' % addr)
                fun = self.relocate_funs[comm][addr]
            elif comm in self.ida_funs:
                #self.lgr.debug('funMgr funFromAddr 0x%x not in relocate' % addr)
                fun = self.ida_funs[comm].getFunName(addr)
        return fun

    def getFunName(self, addr):
        comm = self.getComm()
        ''' Return the function name of the function containing a given IP (loaded) '''
        retval = None
        if comm not in self.ida_funs:
            self.lgr.debug('funMgr getFunName, ida_funs is not defined for comm %s' % comm)
        else: 
            retval = self.ida_funs[comm].getFunName(addr)
        return retval

    def isIterator(self, addr):
        comm = self.getComm()
        if comm in self.user_iterators and self.user_iterators[comm] is not None:
            return self.user_iterators[comm].isIterator(addr)

    def setUserIterators(self, iterators):
        comm = self.getComm()
        self.user_iterators[comm] = iterators

    def addIterator(self, fun):
        comm = self.getComm()
        if comm in self.user_iterators:
            self.user_iterators[comm].add(fun)

    def hasIDAFuns(self, comm=None):
        if comm is None:
            comm = self.getComm()
        else:
            comm = self.getComm(comm_in=comm)
        if comm in self.ida_funs: 
            return True
        else:
            self.lgr.debug('funMgr hasIDAFuns, no funs for comm %s list is:' % (comm))
            for c in self.ida_funs:
                self.lgr.debug('\t %s' % c)
            return False


    def getIDAFuns(self, full_path, root_prefix, offset):
        comm = self.getComm()
        # The offset value will be zero for executables that are not dynamically located.
        # It will be the load address for dynamically located binaries.
        if not self.top.isWindows():
            ''' much of the link mess is due to linux target file systems with links.  Also using links while
                figuring out the windows directory structures. '''
            full_path = resimUtils.realPath(full_path)
        self.lgr.debug('getIDAFuns comm %s full_path %s  root_prefix %s' % (comm, full_path, root_prefix))
        if full_path.startswith(root_prefix):
            analysis_path = self.top.getAnalysisPath(full_path)
            #self.lgr.debug('getIDAFuns analysis_path %s' % analysis_path) 
            if analysis_path is None:
                self.lgr.error('funMgr getIDAFuns, no analysis found for  %s, will not be able to debug' % full_path)
                return
            fun_path = analysis_path+'.funs'
            iterator_path = analysis_path+'.iterators'
            root_dir = os.path.basename(root_prefix)
            self.user_iterators[comm] = userIterators.UserIterators(iterator_path, self.lgr, root_dir)
            
            if os.path.isfile(fun_path):
                self.ida_funs[comm] = idaFuns.IDAFuns(fun_path, self.lgr, offset=offset)
                self.setRelocateFuns(analysis_path, offset=offset)
                self.setArmBLR(analysis_path, offset=offset)
                self.lgr.debug('getIDAFuns for comm %s using IDA function analysis from %s' % (comm, fun_path))
            else:
                self.lgr.error('getIDAFuns No IDA function file at %s' % fun_path)
                #self.getIDAFunsOld(full_path, root_prefix)
                #self.setRelocateFuns(full_path)

        else:
            self.lgr.error('getIDAFuns full path %s does not start with prefix %s' % (full_path, root_prefix))

    def setRelocateFuns(self, full_path, offset=0):
        comm = self.getComm()
        if comm not in self.relocate_funs:
            self.relocate_funs[comm] = {}
        #self.lgr.debug('funMgr setRelocateFuns %s offset is 0x%x' % (full_path, offset))
        if full_path.endswith('.funs'):
            full_path = full_path[:-5]
        relocate_path = full_path+'.imports'
        if os.path.isfile(relocate_path):
            with open(relocate_path) as fh:
                funs = json.load(fh)
                for addr_s in funs:
                    demang = self.demangle(funs[addr_s])
                    if demang is not None:
                        rel_fun_name = demang
                    else:
                        rel_fun_name = funs[addr_s]
                    rel_fun_name = idaFuns.rmPrefix(rel_fun_name)

                    addr = int(addr_s)
                    adjust = addr+offset
                    #if 'FNET' in relocate_path:
                    #    self.lgr.debug('funMgr setRelocateFuns addr 0x%x offset 0x%x adjusted [0x%x] to %s' % (addr, offset, adjust, funs[addr_s]))
                    if adjust in self.relocate_funs[comm]:
                        #self.lgr.debug('funMgr 0x%x already in relocate as %s' % (adjust, self.relocate_funs[adjust]))
                        pass
                    else:
                        self.relocate_funs[comm][adjust] = rel_fun_name
                        #self.lgr.debug('relocate: %s' % rel_fun_name)
                self.lgr.debug('funMgr setRelocateFuns loaded %s relocates for path %s num relocates now %s' % (len(funs), relocate_path, len(self.relocate_funs[comm]))) 
        elif False and not self.top.isWindows():
            #TBD Fix this
            prog_path = self.top.getFullPath()
            ''' TBD need to adjust per offset?'''
            new_relocate_funs = elfText.getRelocate(prog_path, self.lgr, self.ida_funs)
            if new_relocate_funs is not None:
                for fun in new_relocate_funs:
                    self.relocate_funs[comm][fun] = new_relocate_funs[fun]
                self.lgr.warning('funMgr setRelocateFuns no file at %s, revert to elf parse got %d new relocate funs' % (relocate_path, len(new_relocate_funs)))
         
    def getCallRegValue(self, reg, recent_instructs):
        retval = None
        for instruct in reversed(recent_instructs):
            if instruct.startswith('mov'):
                op2, op1 = self.decode.getOperands(instruct)
                if op1 == reg:
                    try:
                        #value = int(op2, 16) 
                        value = self.decode.getAddressFromOperand(self.cpu, op2, self.lgr)
                        retval = value
                        self.lgr.debug('funMgr getCallRegValue got address mov to %s 0x%x' % (reg, retval))
                    except:
                        self.lgr.debug('funMgr getCallRegValue failed getting address for %s' % instruct)
                        break
                        pass
        if retval is None:
            retval = self.mem_utils.getRegValue(self.cpu, reg)
            self.lgr.debug('funMgr getCallRegValue failed getting address mov to %s from recent instructs, use reg value: 0x%x' % (reg, retval))
          
        return retval

    def getFunNameFromInstruction(self, instruct, eip, recent_instructs=[], check_reg=False):
        ''' get the called function address and its name, if known '''
        # TBD duplicates much of resolveCall.  merge?
        #self.lgr.debug('funMgr getFunNameFromInstruct insturct: %s' % instruct[1])
        if self.cpu.architecture != 'arm' and instruct[1].startswith('jmp dword'):
            parts = instruct[1].split()
            addrbrack = parts[3].strip()
            addr = None
            try:
                addr = int(addrbrack[1:-1], 16)
            except:
                #self.lgr.debug('funMgr expected jmp address %s' % instruct[1])
                return None, None
            fun = self.funFromAddr(addr)
            if fun is None:
                call_addr = self.mem_utils.readAppPtr(self.cpu, addr)
                fun = self.funFromAddr(call_addr)
                #self.lgr.debug('funMgr fun from addr 0x%x was None used readAddPtr to get call_addr 0x%x' % (addr, call_addr))
            else:
                #self.lgr.debug('funMgr got fun %s from addr 0x%x' % (fun, addr))
                call_addr = addr
            #self.lgr.debug('getFunName addr 0x%x, call_addr 0x%x got %s' % (addr, call_addr, fun))
 
        else:
            parts = instruct[1].split()
            call_addr = None
            fun = None
            #self.lgr.debug('funMgr getFunNameFromInstruction for %s' % instruct[1])
            if parts[-1].strip().endswith(']'):
                #self.lgr.debug('funMgr getFunNameFromInstruction is bracket %s' % instruct[1])
                call_addr, fun = self.indirectCall(instruct, eip)
          
            elif len(parts) == 2:
                if check_reg and self.mem_utils.isReg(parts[1]): 
                    #call_addr = self.mem_utils.getRegValue(self.cpu, parts[1])
                    call_addr = self.getCallRegValue(parts[1], recent_instructs)
                else:
                    try:
                        call_addr = int(parts[1],16)
                    except ValueError:
                        #self.lgr.debug('getFunName, %s not a hex' % parts[1])
                        pass
                if call_addr is not None:
                    fun = self.funFromAddr(call_addr)
                    #self.lgr.debug('funMgr getFunNameFromInstruction call_addr 0x%x got %s' % (call_addr, fun))
        if fun is not None and (fun.startswith('.') or fun.startswith('_')):
            fun = fun[1:]
        #if call_addr is not None:
            #self.lgr.debug('funMgr getFunNameFromInstruction returning 0x%x %s' % (call_addr, fun))
        return call_addr, fun

    def resolveCall(self, instruct, eip):      
        ''' given a call 0xdeadbeef, convert the instruction to use the function name if we can find it'''
        retval = instruct[1]
        fun_name = None
        self.lgr.debug('funMgr resolveCall %s' % instruct[1])
        if instruct[1].startswith(self.callmn):
            faddr = None
            parts = instruct[1].split()
            if len(parts) < 2:
                # TBD fix for ppc32
                return retval
            if parts[-1].strip().endswith(']'):
                faddr, fun_name = self.indirectCall(instruct, eip)
            else:
                try:
                    faddr = int(parts[1], 16)
                    #print('faddr 0x%x' % faddr)
                except ValueError:
                    pass
                if faddr is not None:
                    fun_name = self.funFromAddr(faddr)
            if fun_name is not None:
                if fun_name.startswith('.') or fun_name.startswith('_'):
                    fun_name = fun_name[1:]
                retval = '%s %s' % (self.callmn, fun_name)
                #self.lgr.debug('resolveCall got %s' % retval)
        return retval
   
    def isRelocate(self, addr):
        retval = False
        comm = self.getComm()
        if comm in self.relocate_funs:
            if addr in self.relocate_funs[comm]:
                retval = True
        return retval

    def showRelocate(self, search=None):
        comm = self.getComm()
        print('showRelocate for comm %s' % comm)
        if comm in self.relocate_funs and fun in self.relocate_funs[comm]:
            for fun in sorted(self.relocate_funs[comm]):
                if search is None or search in self.relocate_funs[comm][fun]:
                    print('0x%x %s' % (fun, self.relocate_funs[comm][fun]))

    def showFuns(self, search = False):
        comm = self.getComm()
        self.ida_funs[comm].showFuns(search=search)

    def showMangle(self, search = False):
        comm = self.getComm()
        self.ida_funs[comm].showMangle(search=search)

    def indirectCall(self, instruct, eip):
            #self.lgr.debug('funMgr indirectCall <%s> eip: 0x%x' % (instruct, eip))
            retval = None
            fun_name = None
            parts = instruct[1].split()
            if parts[-1].strip().endswith(']'):
                s = parts[-1]
                content = s.split('[', 1)[1].split(']')[0]
                #self.lgr.debug('funMgr indirectCall content <%s> eip: 0x%x' % (content, eip))
                if content.startswith('rip+'):
                    offset_s = content[4:]
                    offset = None
                    try:
                        offset = int(offset_s, 16)
                    except:
                        self.lgr.error('funMgr indirectCall did not get offset from %s' % instruct)
                        return None
                    ''' offset is from IP value following execution of instruction '''
                    addr_of_addr = eip + offset + instruct[0]
                    retval = self.mem_utils.readAppPtr(self.cpu, addr_of_addr)
                    fun_name = self.funFromAddr(retval)
                elif content.startswith('ebp+'):
                    #self.lgr.debug('funMgr indirectCall is relative to ebp, use it. content %s' % content)
                    offset_s = content[4:]
                    offset = None
                    try:
                        offset = int(offset_s, 16)
                    except:
                        self.lgr.error('funMgr indirectCall did not get offset from %s' % instruct)
                        return None
                    #self.lgr.debug('funMgr indirectCall offset_s %s offset 0x%x' % (offset_s, offset))
                    ''' offset is from IP value following execution of instruction '''
                    ebp = self.mem_utils.getRegValue(self.cpu, 'ebp')
                    addr_of_addr = ebp + offset 
                    retval = self.mem_utils.readAppPtr(self.cpu, addr_of_addr)
                    fun_name = self.funFromAddr(retval)
                    #self.lgr.debug('funMgr indirectCall ebp+ 0x%x offset 0x%x addr_of_adr 0x%x retval 0x%x fun_name %s' % ((ebp, offset, addr_of_addr, retval, fun_name)))
                    #SIM_break_simulation('remove this')
                else:
                    addr = None
                    try:
                        addr = int(content, 16)
                    except:
                        pass
                    if addr is not None:
                        #self.lgr.debug('funMgr indirectCall got addr 0x%x' % addr)
                        fun_name = self.funFromAddr(addr)
                        if fun_name is None:
                            retval = self.mem_utils.readAppPtr(self.cpu, addr)
                            if retval is not None:
                                #self.lgr.debug('funMgr indirectCall got 0x%x when reading addr' % retval)
                                fun_name = self.funFromAddr(retval)
                                #self.lgr.debug('funMgr indirectCall got fun %s' % fun_name)
                        else: 
                            retval = addr
            #if retval is not None:
            #    self.lgr.debug('funMgr indirectCall returning 0x%x' % retval)
            return retval, fun_name


    def soChecked(self, addr):
        comm = self.getComm()
        if comm in self.so_checked and addr in self.so_checked[comm]:
            return True
        else:
            return False

    def soCheckAdd(self, addr):
        comm = self.getComm()
        if comm not in self.so_checked:
            self.so_checked[comm] = []
        if addr not in self.so_checked[comm]: 
            self.so_checked[comm].append(addr)

    def showFunAddrs(self, fun_name):
        comm = self.getComm()
        if comm not in self.ida_funs:
            print('Comm %s not in ida funs' % comm)
            return
        print('showFunAddrs for comm %s' % comm)
        ''' given a function name, return its entry points? '''
        for fun in self.relocate_funs[comm]:
            if self.relocate_funs[comm][fun] == fun_name:
                print('relocate 0x%x' % fun)
        self.ida_funs[comm].showFunEntries(fun_name)

    def getFunEntry(self, fun_name):
        ''' get the loaded entry address for the named funtion.  If not in the fun list, check the exports.'''
        retval = None
        comm = self.getComm()
        if comm in self.ida_funs:
            retval =  self.ida_funs[comm].getFunEntry(fun_name)
            if retval is None:
                if comm in self.export_funs and fun_name in self.export_funs[comm]:
                   retval = self.ida_funs[comm].getFunLoaded(self.export_funs[comm][fun_name]) 
        else:
            self.lgr.error('funMgr called but no IDA functions defined')
        return retval

    def getFunWithin(self, fun_name, start, end):
        comm = self.getComm()
        if comm in self.ida_funs:
            return self.ida_funs[comm].getFunWithin(fun_name, start, end)
        else:
            self.lgr.error('funMgr getFunWithin called but no IDA functions defined for comm %s' % comm)

    def traceFuns(self):
        ''' generate trace messages for each function call within the target. 
            TBD assumes arm and only outputs to log. '''
        funs = self.ida_funs.getFuns()
        bp_start = None
        self.trace_addrs = []
        tid = self.top.getTID()
        for f in funs:
            addr = funs[f]['start']
            self.trace_addrs.append(addr)
            bp = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, addr, 1, 0)
            self.lgr.debug('funMgr traceFuns fun 0x%x start 0x%x bp: 0x%x' % (f, addr, bp))
            if bp_start is None:
                bp_start = bp
            self.fun_break[addr] = bp
        self.fun_hap = SIM_hap_add_callback_range("Core_Breakpoint_Memop", self.funHap, tid, bp_start, bp)

    def funHap(self, want_tid, conf_object, break_num, memory):
        # entered when a global symbol was hit.
        addr = memory.logical_address
        if addr not in self.trace_addrs:
            # callback_range is an attractive nuisance
            return
        tid = self.top.getTID()
        if tid != want_tid:
            self.lgr.debug('funMgr funHap wrong tid want %s got %s' % (want_tid, tid))
            return    
        #ttbr = self.cpu.translation_table_base0
        #cpu = SIM_current_processor()
        reg_num = self.cpu.iface.int_register.get_number('pc')
        pc_value = self.cpu.iface.int_register.read(reg_num)
        reg_num = self.cpu.iface.int_register.get_number('lr')
        lr_value = self.cpu.iface.int_register.read(reg_num)
        fun = self.ida_funs.getFunName(addr)
        fun_from = self.ida_funs.getFunName(lr_value)
        self.lgr.debug('funHap addr: 0x%x lr: 0x%x fun: %s from: %s break_num: 0x%x cycle: 0x%x' % (addr, lr_value, fun, fun_from, break_num, self.cpu.cycles))
            
    def getStartEnd(self, fun):
        comm = self.getComm()
        return self.ida_funs[comm].getAddr(fun)

    def stackAdjust(self, fun):
        comm = self.getComm()
        retval = 0
        if comm in self.ida_funs:
            retval = self.ida_funs[comm].stackAdjust(fun)
        return retval

    def setArmBLR(self, full_path, offset=0):
        comm = self.getComm()
        if comm not in self.call_reg_funs:
            self.call_reg_funs[comm] = {}
        if full_path.endswith('.funs'):
            full_path = full_path[:-5]
        suffix_list = ['.arm_blr', '.x86_call_reg']
        for suffix in suffix_list:
            blr_path = full_path+suffix
            if os.path.isfile(blr_path):
                with open(blr_path) as fh:
                    funs = json.load(fh)
                    for addr_s in funs:
                        blr_fun_name = funs[addr_s]
                        blr_fun_name = idaFuns.rmPrefix(blr_fun_name)
                        addr = int(addr_s)
                        adjust = addr+offset
                        if adjust in self.call_reg_funs[comm]:
                            #self.lgr.debug('funMgr 0x%x already in call_reg_funs as %s' % (adjust, self.call_reg_funs[adjust]))
                            pass
                        else:
                            self.call_reg_funs[comm][adjust] = blr_fun_name
                            #self.lgr.debug('funMgr blr adjust 0x%x to %s' % (adjust, blr_fun_name))
                    self.lgr.debug('funMgr setArmBLR loaded %s blr_funs for path %s num blrs now %s' % (len(funs), blr_path, len(self.call_reg_funs[comm]))) 
        else:
            self.lgr.debug('setArmBLR no file at %s' % blr_path)
       
    def getBlr(self, addr): 
        retval = None
        comm = self.getComm()
        if addr in self.call_reg_funs[comm]:
            retval = self.call_reg_funs[comm][addr]
            self.lgr.debug('funMgr getBlr addr 0x%x return %s' % (addr, retval))
        return retval

    def haveFuns(self, fname):
        comm = self.getComm()
        if comm in self.ida_funs:
            return self.ida_funs[comm].haveFuns(fname)
        else:
            return None

    def loadExports(self, full_path):
        self.lgr.debug('funMgr loadExports for %s' % full_path)
        comm = self.getComm()
        if comm not in self.export_funs:
            self.export_funs[comm] = {}
        if full_path.endswith('.funs'):
            full_path = full_path[:-5]
        export_path = full_path+'.exports'
        if os.path.isfile(export_path):
            with open(export_path) as fh:
                exports = json.load(fh)
                for fname in exports:
                    fun_name = idaFuns.rmPrefix(fname)
                    self.export_funs[comm][fun_name] = exports[fname]['start']
                    #self.lgr.debug('\t%s - 0x%x' % (fun_name, exports[fname]['start']))
        else:
            self.lgr.debug('funMgr loadExports failed to find %s' % full_path)
                
