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
from simics import *
import json
import os
import memUtils
import decode
import decodeArm
class StackTrace():
    class FrameEntry():
        def __init__(self, ip, fname, instruct, sp, ret_addr=None, fun_addr=None, fun_name=None, lr_return=False, ret_to_addr=None):
            self.ip = ip
            self.fname = fname
            self.instruct = instruct
            self.sp = sp
            self.ret_addr = ret_addr
            self.fun_addr = fun_addr
            self.fun_name = fun_name
            self.fun_of_ip = None
            self.lr_return = lr_return
            self.ret_to_addr = ret_to_addr
        def dumpString(self):
            if self.ret_addr is not None:
                return 'ip: 0x%x fname: %s instruct: %s sp: 0x%x ret_addr: 0x%x' % (self.ip, self.fname, self.instruct, self.sp, self.ret_addr)
            else:
                return 'ip: 0x%x fname: %s instruct: %s sp: 0x%x ' % (self.ip, self.fname, self.instruct, self.sp)

    def __init__(self, top, cpu, pid, soMap, mem_utils, task_utils, stack_base, ida_funs, targetFS, 
                 relocate_funs, reg_frame, lgr, max_frames=None, max_bytes=None):
        self.top = top
        self.cpu = cpu
        if self.cpu.architecture == 'arm':
            self.decode = decodeArm
        else:
            self.decode = decode
        self.pid = pid
        self.lgr = lgr
        self.soMap = soMap
        self.targetFS = targetFS
        self.frames = []
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.stack_base = stack_base
        self.ida_funs = ida_funs
        self.reg_frame = reg_frame
        self.max_frames = max_frames
        ''' limit how far down the stack we look for calls '''
        self.max_bytes = max_bytes 
        self.relocate_funs = relocate_funs
        if cpu.architecture == 'arm':
            self.callmn = 'bl'
            self.jmpmn = 'bx'
        else:
            self.callmn = 'call'
            self.jmpmn = 'jmp'

        if pid == 0:
            lgr.error('stackTrace asked to trace pid 0?')
            return
        self.doTrace()

    def isCallTo(self, instruct, fun):
        if instruct.startswith(self.callmn):
            parts = instruct.split()
            if parts[1].startswith(fun):
                return True
        return False
            
            
    def followCall(self, return_to):
        ''' given a returned to address, look backward for the address of the call instruction '''
        retval = None
        if return_to == 0 or not self.soMap.isCode(return_to, self.pid):
            return None
        if self.cpu.architecture == 'arm':
            #self.lgr.debug('followCall return_to 0x%x' % return_to)
            eip = return_to - 4
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            #self.lgr.debug('followCall instruct is %s' % instruct[1])
            if self.decode.isCall(self.cpu, instruct[1]):
                #self.lgr.debug('followCall arm eip 0x%x' % eip)
                retval = eip
        else:
            eip = return_to - 2
            #self.lgr.debug('followCall return_to is 0x%x  ip 0x%x' % (return_to, eip))
            # TBD use instruction length to confirm it is a true call
            # not always 2* word size?
            count = 0
            while retval is None and count < 4*self.mem_utils.WORD_SIZE:
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                #self.lgr.debug('stackTrace followCall eip 0x%x instruct %s' % (eip, instruct[1]))
                ''' TBD hack.  Fix this by getting bb start and walking forward '''
                if instruct[1].startswith(self.callmn) and 'call far ' not in instruct[1]:
                    parts = instruct[1].split()
                    if len(parts) == 2:
                        try:
                            dst = int(parts[1],16)
                        except:
                            retval = eip
                            continue
                        if self.soMap.isCode(dst, self.pid):
                            retval = eip
                        else:
                            #self.lgr.debug('stackTrace dst not code 0x%x' % dst)
                            eip = eip-1
                    else:        
                        retval = eip
                else:
                    eip = eip-1
                count = count+1
        return retval

    def getJson(self):
        retval = []
        for frame in self.frames:
            item = {}
            item['ip'] = frame.ip
            item['fname'] = frame.fname
            item['instruct'] = frame.instruct
            item['fun_of_ip'] = frame.fun_of_ip
            retval.append(item)
        return json.dumps(retval)

    def getFrames(self, count):
        retval = []
        max_index = min(count, len(self.frames))
        for i in range(max_index):
            retval.append(self.frames[i])
        return retval

    def getFrameIPs(self):
        retval = []
        for f in self.frames:
            retval.append(f.ip)
        return retval

    def printTrace(self, verbose=False):
        for frame in self.frames:
            if frame.fname is not None:
                fname = os.path.basename(frame.fname)
            else:
                fname = 'unknown'
            sp_string = ''
            if verbose:
                sp_string = ' sp: 0x%x' % frame.sp
            fun_of_ip = None
            if self.ida_funs is not None:
                fun_addr = self.ida_funs.getFun(frame.ip)
                fun_of_ip = self.ida_funs.getName(fun_addr)
                if fun_addr is not None:
                    self.lgr.debug('printTrace fun_addr 0x%x  fun_of_ip %s' % (fun_addr, fun_of_ip))
            if frame.instruct.startswith(self.callmn):
                parts = frame.instruct.split()
                try:
                    faddr = int(parts[1], 16)
                    #print('faddr 0x%x' % faddr)
                except:
                    print('%s 0x%08x %s %s %s' % (sp_string, frame.ip, fname, frame.instruct, fun_of_ip))
                    continue
                fun_name = None
                if self.ida_funs is not None:
                    fun_name = self.ida_funs.getName(faddr)
                if fun_name is not None:
                    print('%s 0x%08x %s %s %s %s' % (sp_string, frame.ip, fname, self.callmn, fun_name, fun_of_ip))
                else:
                    #print('nothing for 0x%x' % faddr)
                    print('%s 0x%08x %s %s %s' % (sp_string, frame.ip, fname, frame.instruct, fun_of_ip))
            else:
                if fun_of_ip is not None: 
                    print('%s 0x%08x %s %s %s' % (sp_string, frame.ip, fname, frame.instruct, fun_of_ip))
                else:
                    print('%s 0x%08x %s %s' % (sp_string, frame.ip, fname, frame.instruct))

    def funFromAddr(self, addr):
        fun = None
        if addr in self.relocate_funs:
            fun = self.relocate_funs[addr]
        elif self.ida_funs is not None:
            #self.lgr.debug('stackTrace funFromAddr 0x%x not in relocate' % addr)
            fun = self.ida_funs.getName(addr)
        return fun

    def getFunName(self, instruct):
        ''' get the called function address and its name, if known '''
        if self.cpu.architecture != 'arm' and instruct.startswith('jmp dword'):
            parts = instruct.split()
            addrbrack = parts[3].strip()
            addr = None
            try:
                addr = int(addrbrack[1:-1], 16)
            except:
                #self.lgr.error('stackTrace expected jmp address %s' % instruct)
                return None, None
            fun = str(self.funFromAddr(addr))
            if fun is None:
                call_addr = self.mem_utils.readPtr(self.cpu, addr)
                fun = str(self.funFromAddr(call_addr))
            else:
                call_addr = addr
            #self.lgr.debug('getFunName addr 0x%x, call_addr 0x%x got %s' % (addr, call_addr, fun))
 
        else:
            parts = instruct.split()
            if len(parts) != 2:
                #self.lgr.debug('stackTrace getFunName not a call? %s' % instruct)
                return None, None
            fun = None
            call_addr = None
            try:
                call_addr = int(parts[1],16)
                fun = str(self.funFromAddr(call_addr))
                #self.lgr.debug('getFunName call_addr 0x%x got %s' % (call_addr, fun))
            except ValueError:
                #self.lgr.debug('getFunName, %s not a hex' % parts[1])
                pass
        return call_addr, fun

    def isCallToMe(self, fname, eip):
        ''' if LR looks like a call to current function, add frame? '''
        retval = eip
        if self.cpu.architecture == 'arm':
            ''' macro-type calls, e.g., memset don't bother with stack frame return value? '''
            '''
            cpl = memUtils.getCPL(self.cpu)
            if cpl == 0:
                lr = self.mem_utils.getRegValue(self.cpu, 'lr_usr')
            else:
                lr = self.mem_utils.getRegValue(self.cpu, 'lr')
            '''
            lr = self.reg_frame['lr']
            ''' TBD also for 64-bit? '''
            call_instr = lr-4
            #self.lgr.debug("isCallToMe call_instr 0x%x  eip 0x%x" % (call_instr, eip))
            if self.ida_funs is not None:
                cur_fun = self.ida_funs.getFun(eip)
                if cur_fun is not None:
                    fun_name = self.ida_funs.getName(cur_fun)
                    #self.lgr.debug('isCallToMe eip: 0x%x is in fun %s 0x%x' % (eip, fun_name, cur_fun))
                ret_to = self.ida_funs.getFun(lr)
                if cur_fun is not None and ret_to is not None:
                    #self.lgr.debug('isCallToMe eip: 0x%x (cur_fun 0x%x) lr 0x%x (ret_to 0x%x) ' % (eip, cur_fun, lr, ret_to))
                    pass
                if cur_fun != ret_to:
                    try:
                        instruct = SIM_disassemble_address(self.cpu, call_instr, 1, 0)
                    except OverflowError:
                        #self.lgr.debug('StackTrace isCallToMe could not get instruct from 0x%x' % call_instr)
                        return retval 
                    if instruct[1].startswith(self.callmn):
                        fun_hex, fun = self.getFunName(instruct[1])
                        if fun_hex is None:
                            #self.lgr.debug('stackTrace fun_hex was None for instruct %s at 0x%x' % (instruct[1], call_instr))
                            pass
                        elif cur_fun is not None:
                            #self.lgr.debug('isCallToMe is call fun_hex is 0x%x fun %s cur_fun %x' % (fun_hex, fun, cur_fun))
                            pass
                        if fun_hex is not None and fun_hex == cur_fun:
                            if fun is not None:
                                new_instruct = '%s   %s' % (self.callmn, fun)
                                #self.lgr.debug('fun not none %s' % fun)
                            else:
                                ''' TBD do we ever get here?'''
                                #self.lgr.debug('fun is None')
                                if fun_hex in self.relocate_funs:
                                    fun = self.relocate_funs[fun_hex]
                                    new_instruct = '%s   0x%x' % (self.callmn, fun)
                                    #self.lgr.debug('fun relocate %s' % fun)
                                else:
                                    #self.lgr.debug('fun_hex is 0x%x' % fun_hex)
                                    new_instruct = '%s   0x%x' % (self.callmn, fun_hex)
                            frame = self.FrameEntry(call_instr, fname, new_instruct, 0, ret_addr=lr, fun_addr=fun_hex, fun_name = fun, lr_return=True)
                            self.addFrame(frame)
                            #self.lgr.debug('isCallToMe adding frame %s' % frame.dumpString())
                            retval = lr
                        elif fun_hex is not None:
                            ''' LR does not suggest call to current function. Is current a different library then LR? '''
                            #self.lgr.debug('try got')
                            if self.tryGot(lr, eip, fun_hex):
                                new_instruct = '%s   %s' % (self.callmn, fun)
                                call_fname, dumb1, dumb2 = self.soMap.getSOInfo(call_instr)
                                frame = self.FrameEntry(call_instr, call_fname, new_instruct, 0, ret_addr=lr, fun_addr=fun_hex, fun_name = fun, lr_return=True)
                                self.addFrame(frame)
                                #self.lgr.debug('isCallToMe got adding frame %s' % frame.dumpString())
                                retval = lr
        return retval

    def tryGot(self, lr, eip, fun_hex):
        retval = False
        cur_lib = self.soMap.getSOFile(eip)
        lr_lib = self.soMap.getSOFile(lr)
        if cur_lib != lr_lib:
            ''' is 2nd instruction a load of PC? '''
            instruct = SIM_disassemble_address(self.cpu, fun_hex, 1, 0)
            second_fun_eip = fun_hex + instruct[0]
            second_instruct = SIM_disassemble_address(self.cpu, second_fun_eip, 1, 0)
            #self.lgr.debug('1st %s 2nd %s' % (instruct[1], second_instruct[1]))
            parts = second_instruct[1].split()
            if parts[0].upper() == "LDR" and parts[2].upper() == "PC,":
                #self.lgr.debug("2nd instruction of 0x%x is ldr pc" % fun_hex)
                retval = True
            else:
                third_fun_eip = fun_hex + instruct[0]+second_instruct[0]
                third_instruct = SIM_disassemble_address(self.cpu, third_fun_eip, 1, 0)
                #self.lgr.debug('3nd %s' % (third_instruct[1]))
                parts = third_instruct[1].split()
                if parts[0].upper() == "LDR" and parts[1].upper() == "PC,":
                    #self.lgr.debug("3nd instruction of 0x%x is ldr pc" % fun_hex)
                    retval = True
        return retval

    def funMatch(self, fun1, fun2):
        # TBD make data files for libc fu?
        retval = False
        if fun1.startswith(fun2) or fun2.startswith(fun1):
            retval = True
        else:
            if (fun1 == 'timelocal' and fun2 == 'mktime') or (fun1 == 'mktime' and fun2 == 'timelocal'):
                retval = True
        return retval

    def doX86(self):
        eip = self.reg_frame['pc']
        esp = self.reg_frame['sp']
        bp = self.mem_utils.getRegValue(self.cpu, 'ebp')
        #self.lgr.debug('dox86 eip:0x%x esp:0x%x bp:0x%x' % (eip, esp, bp))
        cur_fun = None
        quick_return = None
        cur_fun_name = None
        if self.ida_funs is not None:
            cur_fun = self.ida_funs.getFun(eip)
        if cur_fun is None:
            #self.lgr.debug('stackTrace doX86, curFun for eip 0x%x is NONE' % eip)
            pass
        else:
            #self.lgr.debug('stackTrace doX86 cur_fun is 0x%x' % cur_fun)
            pass
        if bp == 0:
            self.lgr.debug('bp is zero')
            #ptr = self.findReturnFromCall(esp, cur_fun)
            #self.lgr.debug('doX86, bp is zero, tried findReturn, ptr now 0x%xx' % (ptr))
            bp = self.mem_utils.readPtr(self.cpu, esp)
            #self.lgr.debug('doX86, bp is zero, tried findReturn, read bp from stack, is 0x%x' % (bp))
        else:
            ''' look for call return that is within a few bytes of SP'''
            #self.lgr.debug('doX86,  look for call return that is within a few bytes of SP')
            if cur_fun is not None:
                cur_fun_name = self.funFromAddr(cur_fun)
            #if self.ida_funs is not None:
            #    cur_fun_name = self.ida_funs.getFun(eip)
            if cur_fun is not None and cur_fun_name is not None:
                #self.lgr.debug('doX86, cur_fun 0x%x name %s' % (cur_fun, cur_fun_name))
                pass
            quick_return = self.findReturnFromCall(esp, cur_fun, max_bytes=18, eip=eip)


        if quick_return is None:
            ''' adjust first frame to have fun_addr and ret_addr '''
            pushed_bp = self.mem_utils.readPtr(self.cpu, bp)
            ret_to_addr = bp + self.mem_utils.WORD_SIZE
            ret_to = self.mem_utils.readPtr(self.cpu, ret_to_addr)
            self.frames[0].ret_addr = ret_to
            self.frames[0].ret_to_addr = ret_to_addr
            self.frames[0].fun_addr = cur_fun
            self.frames[0].fun_name = cur_fun_name
            #if cur_fun is not None and ret_to is not None:
            #    self.lgr.debug('doX86, set frame 0 ret_to_addr 0x%x  ret_addr 0x%x  fun_addr 0x%x' % (ret_to_addr, ret_to, cur_fun))
            #else:
            #    self.lgr.debug('doX86, set frame 0 ret_to or cur_fun is None')
        
        while True:
            if bp == 0 and len(self.frames)>1:
                break
            pushed_bp = self.mem_utils.readPtr(self.cpu, bp)
            if pushed_bp == bp:
                #self.lgr.debug('stackTrace doX86, pushed bp same as bp, bail')
                break
            ret_to_addr = bp + self.mem_utils.WORD_SIZE
            ret_to = self.mem_utils.readPtr(self.cpu, ret_to_addr)
            if ret_to is None:
                break
            #self.lgr.debug('stackTrace doX86 ret_to is 0x%x, addr was 0x%x' % (ret_to, ret_to_addr))
            call_inst = self.followCall(ret_to)
            if call_inst is not None:
                instruct = SIM_disassemble_address(self.cpu, call_inst, 1, 0)[1]
                call_addr, fun_name = self.getFunName(instruct)
                instruct = self.resolveCall(instruct)
        
                if call_addr is not None:
                    #if cur_fun is not None:
                    #    self.lgr.debug('stackTrace x86 call addr 0x%x fun %s cur_fun: 0x%x' % (call_addr, fun_name, cur_fun))
                    #else:
                    #    self.lgr.debug('stackTrace x86 call addr 0x%x fun %s cur_fun is None' % (call_addr, fun_name))
                    #self.lgr.debug('stackTrace 8x86 pushed bp is 0x%x' % pushed_bp)
                    if call_addr != cur_fun and quick_return is None:
                        self.findReturnFromCall(esp, cur_fun)
                   
                    
                else:
                    #self.lgr.debug('stackTrace x86, no call_addr for %s' % instruct)
                    pass
                if self.ida_funs is not None: 
                    cur_fun = self.ida_funs.getFun(ret_to)
                bp = pushed_bp
                fname = self.soMap.getSOFile(call_addr)
                if fname is None:
                    fname = 'unknown'
                #self.lgr.debug('stackTrace x86 frame add call_inst 0x%x  inst: %s' % (call_inst, instruct)) 
                frame = self.FrameEntry(call_inst, fname, instruct, (bp - self.mem_utils.WORD_SIZE), fun_addr=call_addr, 
                    fun_name=fun_name, ret_addr=ret_to, ret_to_addr = ret_to_addr)
                self.addFrame(frame)
            else:
                #self.lgr.debug('stackTrace 8x6, no call_instr from ret_to 0x%x' % ret_to)
                break
        return bp
    
    def findReturnFromCall(self, ptr, cur_fun, max_bytes=None, eip=None):        
        ''' See if an x86 return instruction is within a few bytes of the SP.  Handles clib cases where ebp is not pushed. 
            Likely more complicated then it needs to be.  Many special cases.'''
        got_fun_name = None
        cur_fun_name = None
        cur_is_clib = False
        if cur_fun is not None:
            cur_fun_name = self.funFromAddr(cur_fun)
            #self.lgr.debug('stackTrace findReturnFromCall ptr 0x%x cur_fun 0x%x (%s)' % (ptr, cur_fun, cur_fun_name))
            pass
        else:
            #self.lgr.debug('stackTrace findReturnFromCall ptr 0x%x cur_fun NONE' % (ptr))
            pass
        esp = self.reg_frame['sp']
        current_instruct = None
        if eip is not None:
            current_instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)[1]
            lib_file = self.top.getSO(eip)
            if lib_file is not None and 'libc' in lib_file.lower():
                cur_is_clib = True
            #self.lgr.debug('stackTrace findReturnFromCall given eip 0x%x, is clib? %r for %s' % (eip, cur_is_clib, current_instruct))
        retval = None
        if max_bytes is None:
            limit = ptr + 500
        else:
            limit = ptr + max_bytes
        while retval is None and ptr < limit:
            val = self.mem_utils.readPtr(self.cpu, ptr)
            if val is None:
                #self.lgr.debug('stackTrace findReturnFromCall, failed to read from 0x%x' % ptr)
                ptr = ptr + self.mem_utils.WORD_SIZE
                done = True
                continue
            # TBD should be part of readPtr?
            if self.mem_utils.WORD_SIZE == 8:
                val = val & 0x0000ffffffffffff
            skip_this = False
            if val == 0:
                ptr = ptr + self.mem_utils.WORD_SIZE
                continue
            #self.lgr.debug('ptr 0x%x val 0x%x  limit 0x%x' % (ptr, val, limit))    
            if self.soMap.isCode(val, self.pid):
                #self.lgr.debug('is conde')
                call_ip = self.followCall(val)
                if call_ip is not None:
                    if cur_fun is None and self.ida_funs is not None:
                        cur_fun = self.ida_funs.getFun(call_ip)
                        if cur_fun is not None:
                            #self.lgr.debug('findReturn had no cur_fun, set to 0x%x' % cur_fun)
                            pass
                        else:
                            #self.lgr.debug('findReturn, still no curfun call_ip was 0x%x' % call_ip)
                            pass
                    instruct_of_call = SIM_disassemble_address(self.cpu, call_ip, 1, 0)
                    instruct = instruct_of_call[1]
                    #self.lgr.debug('got call_ip 0x%x  %s' % (call_ip, instruct))
                    call_addr, fun_name = self.getFunName(instruct)
                    if call_addr == cur_fun:
                        retval = ptr
                        fname = self.soMap.getSOFile(call_ip)
                        frame = self.FrameEntry(call_ip, fname, instruct, ptr, fun_addr=call_addr, fun_name=fun_name, ret_to_addr=ptr)
                        frame.ret_addr = call_ip + instruct_of_call[0] 
                        self.addFrame(frame)
                        mft_ret = self.mem_utils.readPtr(self.cpu, ptr)
                        #self.lgr.debug('Found call to %s instruct:%s  ret_to_addr 0x%x ret 0x%x' % (cur_fun, instruct, ptr, mft_ret))
                    elif call_addr is not None:

                        #if cur_fun is not None:
                        #    self.lgr.debug('call_addr 0x%x  cur_fun 0x%x' % (call_addr, cur_fun))
                        first_instruct = SIM_disassemble_address(self.cpu, call_addr, 1, 0)[1]
                        #self.lgr.debug('first_instruct is %s' % first_instruct)
                        
                        if first_instruct.lower().startswith('jmp dword'):
                            fun_name = None
                            call_addr, fun_name = self.getFunName(first_instruct)
                            instruct = '%s %s' % (self.callmn, fun_name)
                            if call_addr is not None:
                                #self.lgr.debug('is jmp, call_addr now 0x%x' % call_addr)
                                got_fun_name = self.funFromAddr(call_addr)
                                if got_fun_name is None:
                                    got_entry = self.mem_utils.readPtr(self.cpu, call_addr)
                                    got_fun_name = self.funFromAddr(got_entry)
                                    #self.lgr.debug('got got go again fun %s' % got_fun_name)
                                else:
                                    #self.lgr.debug('got got fun %s' % got_fun_name)
                                    pass
                        instruct = self.resolveCall(instruct)
                        if call_addr == cur_fun:
                            retval = ptr
                            fname = self.soMap.getSOFile(call_ip)
                            frame = self.FrameEntry(call_ip, fname, instruct, ptr, fun_addr=call_addr, fun_name=fun_name, ret_to_addr=ptr)
                            frame.ret_addr = call_ip + instruct_of_call[0] 
                            self.addFrame(frame)
                            mft_ret = self.mem_utils.readPtr(self.cpu, ptr)
                            #self.lgr.debug('Found call %s  ret_to_addr 0x%x ret 0x%x' % (instruct, ptr, mft_ret))
                        elif cur_fun_name is not None and got_fun_name is not None and got_fun_name.startswith(cur_fun_name):
                            retval = ptr
                            fname = self.soMap.getSOFile(call_ip)
                            frame = self.FrameEntry(call_ip, fname, instruct, ptr, fun_addr=call_addr, fun_name=cur_fun_name, ret_to_addr=ptr)
                            frame.ret_addr = call_ip + instruct_of_call[0] 
                            self.addFrame(frame)
                            mft_ret = self.mem_utils.readPtr(self.cpu, ptr)
                            #self.lgr.debug('Found GOT call %s  is got %s   add entry  call_ip 0x%x  call_addr: 0x%x ret_to_addr: 0x%x ret: 0x%x' % (instruct, got_fun_name, call_ip, call_addr, ptr, mft_ret))
                        elif got_fun_name is not None and cur_is_clib:
                            retval = ptr
                            fname = self.soMap.getSOFile(call_ip)
                            frame = self.FrameEntry(call_ip, fname, instruct, ptr, fun_addr=call_addr, fun_name=got_fun_name, ret_to_addr=ptr)
                            frame.ret_addr = call_ip + instruct_of_call[0] 
                            self.addFrame(frame)
                            mft_ret = self.mem_utils.readPtr(self.cpu, ptr)
                            #self.lgr.debug('Found GOT, though no current fuction found. call %s  is got %s   add entry  call_ip 0x%x  call_addr: 0x%x ret_to_addr: 0x%x ret: 0x%x' % (instruct, 
                            #     got_fun_name, call_ip, call_addr, ptr, mft_ret))
                        elif got_fun_name is not None:
                            retval = ptr
                            fname = self.soMap.getSOFile(call_ip)
                            frame = self.FrameEntry(call_ip, fname, instruct, ptr, fun_addr=call_addr, fun_name=got_fun_name, ret_to_addr=ptr)
                            frame.ret_addr = call_ip + instruct_of_call[0] 
                            self.addFrame(frame)
                            mft_ret = self.mem_utils.readPtr(self.cpu, ptr)
                            #self.lgr.debug('Found GOT, though current fuction is not called function. call %s  is got %s   add entry  call_ip 0x%x  call_addr: 0x%x ret_to_addr: 0x%x ret: 0x%x' % (instruct, 
                            #     got_fun_name, call_ip, call_addr, ptr, mft_ret))
                        elif (fun_name is not None and fun_name.startswith('memcpy')) and (current_instruct is not None and current_instruct.startswith('rep movsd')):
                            # hacks are us
                            retval = ptr
                            fname = self.soMap.getSOFile(call_ip)
                            frame = self.FrameEntry(call_ip, fname, instruct, ptr, fun_addr=call_addr, fun_name=fun_name, ret_to_addr=ptr)
                            frame.ret_addr = call_ip + instruct_of_call[0] 
                            self.addFrame(frame)
                            mft_ret = self.mem_utils.readPtr(self.cpu, ptr)
                            #self.lgr.debug('memcpy/rep mov hack call %s ret_t_addr: 0x%x ret: 0x%x' % (instruct, ptr, mft_ret))
                        else:
                            pass
                            #self.lgr.debug('no radio ')
                            #if call_addr is not None:
                            #    self.lgr.debug('no radio call_addr 0x%x ' % (call_addr))
                            #if cur_fun is not None:
                            #    self.lgr.debug('no radio cur_fun 0x%x ' % (cur_fun))
                #else:
                #    self.lgr.debug('call_ip is None')
            ptr = ptr + self.mem_utils.WORD_SIZE
        return retval                


    def resolveCall(self, instruct):      
        ''' given a call 0xdeadbeef, convert the instruction to use the function name if we can find it'''
        retval = instruct
        if instruct.startswith(self.callmn):
            parts = instruct.split()
            try:
                faddr = int(parts[1], 16)
                #print('faddr 0x%x' % faddr)
                fun_name = None
                if self.ida_funs is not None:
                    #fun_name = self.ida_funs.getName(faddr)
                    fun_name = self.funFromAddr(faddr)
                if fun_name is not None:
                    if fun_name.startswith('.'):
                        fun_name = fun_name[1:]
                    retval = '%s %s' % (self.callmn, fun_name)
            except ValueError:
                pass
        return retval
    

    def doTrace(self):
        if self.pid == 0 or self.pid == 1:
            #self.lgr.debug('stackTrack doTrace called with pid 0')
            return
        '''
        cpl = memUtils.getCPL(self.cpu)
        if cpl == 0 and self.cpu.architecture == 'arm':
            esp = self.mem_utils.getRegValue(self.cpu, 'sp_usr')
            eip = self.mem_utils.getRegValue(self.cpu, 'lr')-4
        else:
            # TBD user space pc and sp when in kernel 
            esp = self.mem_utils.getRegValue(self.cpu, 'esp')
            eip = self.top.getEIP(self.cpu)
        '''
        esp = self.reg_frame['sp']
        eip = self.reg_frame['pc']
        if self.stack_base is not None:
            #self.lgr.debug('stackTrace doTrace pid:%d esp is 0x%x eip 0x%x  stack_base 0x%x' % (self.pid, esp, eip, self.stack_base))
            pass
        else:
            #self.lgr.debug('stackTrace doTrace NO STACK BASE pid:%d esp is 0x%x eip 0x%x' % (self.pid, esp, eip))
            pass
        done  = False
        count = 0
        #ptr = ebp
        ptr = esp
        been_in_main = False
        prev_ip = None
        so_checked = []
        if self.soMap.isMainText(eip):
            #self.lgr.debug('stackTrace starting in main text set prev_ip to 0x%x' %eip)
            been_in_main = True
            prev_ip = eip
        #prev_ip = eip
        if self.ida_funs is None:
            self.lgr.warning('stackTrace has no ida functions')

        ''' record info about current IP '''
       
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)[1]
        fname = self.soMap.getSOFile(eip)
        prev_fname = fname
        instruct = self.resolveCall(instruct)

        #self.lgr.debug('StackTrace doTrace begin pid:%d cur eip 0x%x instruct %s  fname %s' % (self.pid, eip, instruct, fname))
        if fname is None:
            frame = self.FrameEntry(eip, 'unknown', instruct, esp)
            self.addFrame(frame)
        else:
            frame = self.FrameEntry(eip, fname, instruct, esp)
            self.addFrame(frame)
        #self.lgr.debug('first frame %s' % frame.dumpString())
        ''' TBD *********** DOES this prev_ip assignment break frames that start in libs? '''
        prev_ip = self.isCallToMe(fname, eip)
        #self.lgr.debug('doTrace back from isCallToMe prev_ip set to 0x%x' % prev_ip)
        cur_fun = None
        cur_fun_name = None
        if self.ida_funs is not None:
            cur_fun = self.ida_funs.getFun(eip)
            if prev_ip == eip and cur_fun is not None:
                cur_fun_name = self.ida_funs.getName(cur_fun)
                if cur_fun_name.startswith('.'):
                    cur_fun_name = cur_fun_name[1:]
                #self.lgr.debug('doTrace starting eip: 0x%x is in fun %s 0x%x' % (eip, cur_fun_name, cur_fun))

        if self.cpu.architecture != 'arm':
            bp = self.doX86()
            if bp == 0 and len(self.frames)>1:
                ''' walked full stack '''
                done = True

        while not done and (count < 9000): 
            ''' ptr iterates through stack addresses.  val is the value at that address '''
            val = self.mem_utils.readPtr(self.cpu, ptr)
            if val is None:
                self.lgr.debug('stackTrace, failed to read from 0x%x' % ptr)
                count += 1
                ptr = ptr + self.mem_utils.WORD_SIZE
                done = True
                continue
            # TBD should be part of readPtr?
            if self.mem_utils.WORD_SIZE == 8:
                val = val & 0x0000ffffffffffff
            skip_this = False
            if val == 0:
                count += 1
                ptr = ptr + self.mem_utils.WORD_SIZE
                continue
            #self.lgr.debug('ptr 0x%x val 0x%x' % (ptr, val))    
            if self.soMap.isCode(val, self.pid):
                call_ip = self.followCall(val)
                if call_ip is not None:
                   #self.lgr.debug('is code: 0x%x from ptr 0x%x   PC of call is 0x%x' % (val, ptr, call_ip))
                   pass
                else:
                   #self.lgr.debug('is code not follow call: 0x%x from ptr 0x%x   ' % (val, ptr))
                   pass
                   
                if been_in_main and not self.soMap.isMainText(val):
                    ''' once in main text assume we never leave? what about callbacks?'''
                    skip_this = True
                    
                if been_in_main and self.ida_funs is not None and call_ip is not None and prev_ip is not None:
                #if self.ida_funs is not None and call_ip is not None and prev_ip is not None:
                    instruct = SIM_disassemble_address(self.cpu, call_ip, 1, 0)[1]
                    call_to_s = instruct.split()[1]
                    call_to = None
                    #self.lgr.debug('stackTrace check call to %s' % call_to_s)
                    try:
                        call_to = int(call_to_s, 16)
                    except:
                        pass 
                    if call_to is not None:
                        #self.lgr.debug('call_to 0x%x ' % call_to)
                        if call_to not in so_checked:
                            ''' should we add ida function analysys? '''
                            if not self.ida_funs.isFun(call_to):
                                fname, start, end = self.soMap.getSOInfo(call_to)
                                #self.lgr.debug('so check of %s the call_to of 0x%x not in IDA funs?' % (fname, call_to))
                                if fname is not None:
                                    full_path = self.targetFS.getFull(fname, self.lgr)
                                    self.ida_funs.add(full_path, start)
                            so_checked.append(call_to) 
                        if self.ida_funs.isFun(call_to):
                            if not self.ida_funs.inFun(prev_ip, call_to):
                                first_instruct = SIM_disassemble_address(self.cpu, call_to, 1, 0)[1]
                                #self.lgr.debug('first_instruct is %s' % first_instruct)
                                if self.cpu.architecture == 'arm' and first_instruct.lower().startswith('b '):
                                    fun_hex, fun = self.getFunName(first_instruct)
                                    #self.lgr.debug('direct branch 0x%x %s' % (fun_hex, fun))
                                    if not (self.ida_funs.isFun(fun_hex) and self.ida_funs.inFun(prev_ip, fun_hex)):
                                        skip_this = True
                                        #self.lgr.debug('StackTrace addr (prev_ip) 0x%x not in fun 0x%x, or just branch 0x%x skip it' % (prev_ip, call_to, fun_hex))
                                    else:
                                        ''' record the direct branch, e.g., B fuFun '''
                                        frame = self.FrameEntry(call_to, fname, first_instruct, ptr, fun_addr=fun_hex, fun_name=fun)
                                        #self.lgr.debug('stackTrace direct branch fname: %s frame %s' % (fname, frame.dumpString()))
                                        self.addFrame(frame)
                                elif self.cpu.architecture != 'arm':
                                    if first_instruct.lower().startswith('jmp dword'):
                                        fun_hex, fun = self.getFunName(first_instruct)
                                        if not (self.ida_funs.isFun(fun_hex) and self.ida_funs.inFun(prev_ip, fun_hex)):
                                            skip_this = True
                                            #self.lgr.debug('StackTrace addr (prev_ip) 0x%x not in fun 0x%x, or just branch 0x%x skip it' % (prev_ip, call_to, fun_hex))
                                        else:
                                            ''' record the direct branch, e.g., jmp dword...'''
                                            frame = self.FrameEntry(call_to, fname, first_instruct, ptr, fun_addr=fun_hex, fun_name=fun)
                                            #self.lgr.debug('stackTrace direct branch fname: %s frame %s' % (fname, frame.dumpString()))
                                            self.addFrame(frame)
                                    else:
                                        bp = self.mem_utils.getRegValue(self.cpu, 'ebp')
                                        if (bp + self.mem_utils.WORD_SIZE) != ptr:
                                            skip_this = True
                                            #self.lgr.debug('StackTrace addr (prev_ip) 0x%x not in fun 0x%x, and bp is 0x%x and  ptr is 0x%x skip it' % (prev_ip, call_to, bp, ptr))
                                else:
                                    skip_this = True
                                    #self.lgr.debug('StackTrace addr (prev_ip) 0x%x not in fun 0x%x, skip it' % (prev_ip, call_to))
                        else:
                            tmp_instruct = SIM_disassemble_address(self.cpu, call_to, 1, 0)[1]
                            if tmp_instruct.startswith(self.jmpmn):
                                skip_this = True
                                #self.lgr.debug('stackTrace 0x%x is jump table?' % call_to)
                            elif call_to in self.relocate_funs:
                                self.lgr.debug('stackTrace 0x%x is relocatable, but already in main text, assume noise and skip' % call_to)
                                skip_this = True
                            else:
                                #self.lgr.debug('stackTrace 0x%x is not a function?' % call_to)
                                pass
 
                if call_ip is not None and not skip_this:
                    skip_this = False
                    instruct = SIM_disassemble_address(self.cpu, call_ip, 1, 0)[1]
                    fun_addr = None 
                    fun_name = None 
                    if instruct.startswith(self.callmn):
                        fun_hex, fun = self.getFunName(instruct)
                        if fun is not None:
                            if cur_fun_name is not None:
                                if fun.startswith('.'):
                                    fun = fun[1:]
                                if not self.funMatch(fun, cur_fun_name): 
                                    if self.cpu.architecture != 'arm':
                                        bp = self.mem_utils.getRegValue(self.cpu, 'ebp')
                                        if (bp + self.mem_utils.WORD_SIZE) != ptr:
                                            #self.lgr.debug('StackTrace candidate <%s> does not match <%s> and bp is 0x%x and  ptr is 0x%x skip it' % (fun, cur_fun_name, bp, ptr))
                                            count += 1
                                            ptr = ptr + self.mem_utils.WORD_SIZE
                                            cur_fun_name = None
                                            continue
                                        else:
                                            cur_fun_name = None
                                    else:
                                        #self.lgr.debug('stackTrace candidate function %s does not match current function %s, skipit' % (fun, cur_fun_name))
                                        ''' don't count this against max frames '''
                                        count += 1
                                        ptr = ptr + self.mem_utils.WORD_SIZE
                                        ''' TBD broken hueristic, e.g., sscanf calls strlen. hack for now... '''
                                        cur_fun_name = None
                                        continue
                                else:
                                    ''' first frame matches expected function '''
                                    cur_fun_name = None
                                instruct = '%s   %s' % (self.callmn, fun)
                        if fun_hex is not None:
                            #self.lgr.debug('stackTrace fun_hex 0x%x, fun %s instr %s' % (fun_hex, fun, instruct))
                            self.soCheck(fun_hex)
                                
                        #self.lgr.debug('ADD STACK FRAME FOR 0x%x %s.  prev_ip will become 0x%x' % (call_ip, instruct, call_ip))
                        fname = self.soMap.getSOFile(val)
                        if fname is None:
                            #print('0x%08x  %-s' % (call_ip, 'unknown'))
                            frame = self.FrameEntry(call_ip, 'unknown', instruct, ptr, fun_addr=fun_hex, fun_name=fun)
                            self.addFrame(frame)
                            #self.lgr.debug('stackTrace fname none added frame %s' % frame.dumpString())
                        else:
                            ''' ad-hoc detect clib ghost frames, assume clib does not call other libraries.  exceptions?  TBD '''
                            #if fname.startswith('clib'):
                            #    if not prev_fname.startswith('clib') and not prev_fname.startswith('libpthread'):
                            #        #self.lgr.debug('stackTrace found call from clib to 0x%x, assume a ghost frame')
                            #        skip_this = True        
                            if not skip_this:
                                frame = self.FrameEntry(call_ip, fname, instruct, ptr, fun_addr=fun_hex, fun_name=fun)
                                self.addFrame(frame)
                                #self.lgr.debug('stackTrace fname %s added frame %s' % (fname, frame.dumpString()))
                            else:
                                pass
                                #self.lgr.debug('stackTrace told to skip %s' % frame.dumpString())
                        if not skip_this:
                            prev_fname = fname
                            prev_ip = call_ip
                            if self.soMap.isMainText(call_ip):
                                been_in_main = True
                                #self.lgr.debug('stackTrace been in main')
                    else:
                        #self.lgr.debug('doTrace not a call? %s' % instruct)
                        frame = self.FrameEntry(call_ip, fname, instruct, ptr, None, None)
                        self.addFrame(frame)
                        #self.lgr.debug('stackTrace not a call? %s fname %s, frame %s' % (instruct, fname, frame.dumpString()))
                else:
                    #self.lgr.debug('nothing from followCall')
                    pass
            elif val is not None and val != 0:
                #self.lgr.debug('ptr 0x%x not code 0x%x' % (ptr, val))
                pass
            count += 1
            ptr = ptr + self.mem_utils.WORD_SIZE
            if self.stack_base is not None and ptr > self.stack_base:
                #self.lgr.debug('stackTrace ptr 0x%x > stack_base 0x%x' % (ptr, self.stack_base)) 
                done = True
            elif self.max_frames is not None and len(self.frames)>= self.max_frames:
                #self.lgr.debug('stackFrames got max frames, done max is %d, got %d' % (self.max_frames, len(self.frames)))
                done = True
            elif self.max_bytes is not None and count > self.max_bytes:
                #self.lgr.debug('stackFrames got max bytes %d, done' % self.max_bytes)
                done = True


    def soCheck(self, eip):

        ''' should we add ida function analysis? '''
        if self.ida_funs is not None and not self.ida_funs.isFun(eip):
            fname, start, end = self.soMap.getSOInfo(eip)
            if fname is not None:
                full = self.targetFS.getFull(fname, self.lgr)
                #self.lgr.debug('stackTrace soCheck eip 0x%x not a fun? Adding it.  fname %s full %s start 0x%x' % (eip, fname,full, start))
                self.ida_funs.add(full, start)

    def countFrames(self):
        return len(self.frames)

    def addFrame(self, frame):
        prev_ip = None
        if len(self.frames) > 0:
            prev_ip = self.frames[-1].ip
        if frame.ip != prev_ip:
            if self.ida_funs is not None:
                fun_addr = self.ida_funs.getFun(frame.ip)
                fun_of_ip = self.ida_funs.getName(fun_addr)
                frame.fun_of_ip = fun_of_ip
            self.frames.append(frame)
        else:
            #self.lgr.debug('stackTrace skipping back to back identical calls: %s' % frame.instruct)
            pass
        
