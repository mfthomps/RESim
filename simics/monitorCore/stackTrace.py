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
import resimUtils
def cppClean(fun):
    if fun.startswith('std::'):
        fun = fun[len('std::'):]
        if fun.startswith('__cxx11::'):
            fun = fun[len('__cxx11::'):]
    return fun

class StackTrace():
    class FrameEntry():
        def __init__(self, ip, fname, instruct, sp, ret_addr=None, fun_addr=None, fun_name=None, lr_return=False, ret_to_addr=None):
            ''' ip of the frame, e.g., the address of the call instruction '''
            self.ip = ip
            ''' program file name per SO map '''
            self.fname = fname
            '''  instruction found at ip '''
            self.instruct = instruct
            '''  sp value at frame'''
            self.sp = sp
            '''  where this frame would return to '''
            self.ret_addr = ret_addr
            ''' address of the function that will be called '''
            self.fun_addr = fun_addr
            ''' name of the function that will be called '''
            self.fun_name = fun_name
            ''' fuction contain the ip '''
            self.fun_of_ip = None
            ''' arm lr return value '''
            self.lr_return = lr_return
            ''' where the ret_addr was read from '''
            self.ret_to_addr = ret_to_addr
        def dumpString(self):
            if self.ret_addr is not None:
                return 'ip: 0x%x fname: %s instruct: %s sp: 0x%x ret_addr: 0x%x' % (self.ip, self.fname, self.instruct, self.sp, self.ret_addr)
            else:
                return 'ip: 0x%x fname: %s instruct: %s sp: 0x%x ' % (self.ip, self.fname, self.instruct, self.sp)

    def __init__(self, top, cpu, pid, soMap, mem_utils, task_utils, stack_base, fun_mgr, targetFS, 
                 reg_frame, lgr, max_frames=None, max_bytes=None):
        self.top = top
        self.cpu = cpu
        if self.cpu.architecture == 'arm':
            self.decode = decodeArm
        else:
            self.decode = decode
        self.pid = pid
        self.word_size = soMap.wordSize(pid)
        self.lgr = lgr
        self.soMap = soMap
        self.targetFS = targetFS
        self.frames = []
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.stack_base = stack_base
        self.fun_mgr = fun_mgr
        self.reg_frame = reg_frame
        self.max_frames = max_frames
        ''' limit how far down the stack we look for calls '''
        self.max_bytes = max_bytes 
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
        if return_to <= 10 or not self.soMap.isCode(return_to, self.pid):
            self.lgr.debug('stackTrace followCall 0x%x not code?' % return_to)
            return None
        if self.cpu.architecture == 'arm':
            #self.lgr.debug('followCall return_to 0x%x' % return_to)
            eip = return_to - 4
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            #self.lgr.debug('followCall instruct is %s' % instruct[1])
            if self.decode.isCall(self.cpu, instruct[1], ignore_flags=True):
                #self.lgr.debug('followCall arm eip 0x%x' % eip)
                retval = eip
        else:
            eip = return_to - 2
            #self.lgr.debug('followCall return_to is 0x%x  ip 0x%x' % (return_to, eip))
            # TBD use instruction length to confirm it is a true call
            # not always 2* word size?
            count = 0
            while retval is None and count < 4*self.mem_utils.wordSize(self.cpu) and eip>0:
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                #self.lgr.debug('stackTrace followCall count %d eip 0x%x instruct %s' % (count, eip, instruct[1]))
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
                            self.lgr.debug('stackTrace dst not code 0x%x' % dst)
                            eip = eip-1
                    else:        
                        retval = eip
                elif 'illegal memory mapping' in instruct[1]:
                    break
                else:
                    eip = eip-1
                count = count+1
        #if retval is not None:
        #    self.lgr.debug('followCall return 0x%x' % retval)
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
            if self.fun_mgr is not None:
                fun_of_ip = self.fun_mgr.getFunName(frame.ip)
              
                if fun_of_ip is not None:
                    fun_of_ip = cppClean(fun_of_ip)
            ''' TBD remove this, call instructions should already be fixed up '''
            if False and frame.instruct.startswith(self.callmn):
                parts = frame.instruct.split()
                try:
                    faddr = int(parts[1], 16)
                    #print('faddr 0x%x' % faddr)
                except:
                    print('%s 0x%08x %s %s %s' % (sp_string, frame.ip, fname, frame.instruct, fun_of_ip))
                    continue
                fun_name = None
                if frame.fun_name is not None:
                    fun_name = frame.fun_name
                elif self.fun_mgr is not None:
                    fun_name = self.fun_mgr.getFunName(faddr)
                if fun_name is not None:
                    fun_name = cppClean(fun_name)
                    print('%s 0x%08x %s %s %s %s' % (sp_string, frame.ip, fname, self.callmn, fun_name, fun_of_ip))
                else:
                    #print('nothing for 0x%x' % faddr)
                    print('%s 0x%08x %s %s %s' % (sp_string, frame.ip, fname, frame.instruct, fun_of_ip))
            else:
                if fun_of_ip is not None: 
                    print('%s 0x%08x %s %s %s' % (sp_string, frame.ip, fname, frame.instruct, fun_of_ip))
                else:
                    print('%s 0x%08x %s %s' % (sp_string, frame.ip, fname, frame.instruct))


    def isCallToMe(self, fname, eip):
        ''' if LR looks like a call to current function, add frame? '''
        retval = None
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
            if self.fun_mgr is not None:
                cur_fun = self.fun_mgr.getFun(eip)
                if cur_fun is not None:
                    fun_name = self.fun_mgr.getFunName(cur_fun)
                    #self.lgr.debug('isCallToMe eip: 0x%x is in fun %s 0x%x' % (eip, fun_name, cur_fun))
                ret_to = self.fun_mgr.getFun(lr)
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
                        fun_hex, fun = self.fun_mgr.getFunNameFromInstruction(instruct, call_instr)
                        #if fun_hex is None:
                        #    self.lgr.debug('stackTrace fun_hex was None for instruct %s at 0x%x' % (instruct[1], call_instr))
                        #    pass
                        #elif cur_fun is not None:
                        #    self.lgr.debug('isCallToMe is call fun_hex is 0x%x fun %s cur_fun %x' % (fun_hex, fun, cur_fun))
                        #    pass
                        if fun_hex is not None and fun_hex == cur_fun:
                            if fun is not None:
                                new_instruct = '%s   %s' % (self.callmn, fun)
                                #self.lgr.debug('fun not none %s' % fun)
                            else:
                                new_instruct = '%s   0x%x' % (self.callmn, fun_hex)
                            frame = self.FrameEntry(call_instr, fname, new_instruct, 0, ret_addr=lr, fun_addr=fun_hex, fun_name = fun, lr_return=True)
                            self.addFrame(frame)
                            #self.lgr.debug('isCallToMe add frame %s' % frame.dumpString())
                            retval = lr
                        elif fun_hex is not None:
                            ''' LR does not suggest call to current function. Is current a different library then LR? '''
                            #self.lgr.debug('try got')
                            if self.tryGot(lr, eip, fun_hex):
                                new_instruct = '%s   %s' % (self.callmn, fun)
                                call_fname, dumb1, dumb2 = self.soMap.getSOInfo(call_instr)
                                frame = self.FrameEntry(call_instr, call_fname, new_instruct, 0, ret_addr=lr, fun_addr=fun_hex, fun_name = fun, lr_return=True)
                                self.addFrame(frame)
                                #self.lgr.debug('isCallToMe got add frame %s' % frame.dumpString())
                                retval = lr
        ''' Function is for ARM'''
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
        if fun1 is None or fun2 is None:
            self.lgr.debug('dataWatch funMatch called with fun of None')
            return False
        # TBD make data files for libc fu?
        retval = False
        if fun1.startswith(fun2) or fun2.startswith(fun1):
            retval = True
        else:
            if (fun1 == 'timelocal' and fun2 == 'mktime') or (fun1 == 'mktime' and fun2 == 'timelocal'):
                retval = True
        if not retval and self.cpu.architecture == 'arm':
            ''' TBD seems incomplete.  Should only be meaningful for first frame? '''
            lr = self.mem_utils.getRegValue(self.cpu, 'lr')
            lr_fun_name = self.fun_mgr.funFromAddr(lr)
            #self.lgr.debug('stackTrace funMatch, try lr fun name %s' % lr_fun_name)
            if lr_fun_name is None:
                self.lgr.debug('stackTrace funMatch, lr fun name None for lr 0x%x' % lr)
            else:
                if fun1.startswith(lr_fun_name) or lr_fun_name.startswith(fun1):
                    retval = True
        return retval

    def doX86(self):
        eip = self.reg_frame['pc']
        esp = self.reg_frame['sp']
        bp = self.mem_utils.getRegValue(self.cpu, 'ebp')
        self.lgr.debug('stackTrace dox86 eip:0x%x esp:0x%x bp:0x%x' % (eip, esp, bp))
        cur_fun = None
        quick_return = None
        cur_fun_name = None
        was_clib = False
        prev_sp = esp
        fname = None
        call_inst = None
        if self.fun_mgr is not None:
            cur_fun = self.fun_mgr.getFun(eip)
        #if cur_fun is None:
        #    self.lgr.debug('stackTrace doX86, curFun for eip 0x%x is NONE' % eip)
        #    pass
        #else:
        #    self.lgr.debug('stackTrace doX86 cur_fun is 0x%x' % cur_fun)
        #    pass
        if bp == 0:
            stack_val = self.readAppPtr(esp)
            call_inst = self.followCall(stack_val)
            self.lgr.debug('doX86 bp is zero')
            if call_inst is not None:
                #self.lgr.debug('doX86 initial sp value 0x%x is a return to address.  call_inst: 0x%x' % (stack_val, call_inst))
                instruct = SIM_disassemble_address(self.cpu, call_inst, 1, 0)
                #this_fun_name = self.funFromAddr(cur_fun)
                this_fun_name = 'unknown'
                call_addr, fun_name = self.fun_mgr.getFunNameFromInstruction(instruct, call_inst)
                if fun_name is None or fun_name == 'None':
                    fun_name = this_fun_name
                fname = self.soMap.getSOFile(call_inst)
                instruct_1 = self.fun_mgr.resolveCall(instruct, eip)
                #self.lgr.debug('doX86 initial sp call to fun_name %s resolve call got %s fname %s' % (fun_name, instruct_1, fname))
                was_clib = resimUtils.isClib(fname)
                prev_sp = esp
                frame = self.FrameEntry(call_inst, fname, instruct_1, esp, fun_addr=call_addr, 
                        fun_name=fun_name, ret_addr=stack_val, ret_to_addr = esp)
                self.addFrame(frame)
            #self.lgr.debug('doX86, bp is zero, tried findReturn, read bp from stack, is 0x%x' % (bp))
        else:
            ''' look for call return that is within a few bytes of SP'''
            #self.lgr.debug('doX86,  look for call return that is within a few bytes of SP')
            if cur_fun is not None:
                cur_fun_name = self.fun_mgr.funFromAddr(cur_fun)
            #if self.ida_funs is not None:
            #    cur_fun_name = self.ida_funs.getFun(eip)
            if cur_fun is not None and cur_fun_name is not None:
                #self.lgr.debug('doX86, cur_fun 0x%x name %s' % (cur_fun, cur_fun_name))
                pass
            fname = self.soMap.getSOFile(eip)
            was_clib = resimUtils.isClib(fname)
            #if not self.soMap.isMainText(eip):
            if True:
                ''' TBD need to be smarter to avoid bogus frames.  Cannot rely on not being main because such things are called in static-linked programs. '''
                #self.lgr.debug('doX86 is call do findReturnFromCall esp 0x%x  eip 0x%x' % (esp, eip))
                delta = bp - esp
                num_bytes = min(0x22, delta)
                quick_return = self.findReturnFromCall(esp, cur_fun, max_bytes=num_bytes, eip=eip)
                #quick_return = self.findReturnFromCall(esp, cur_fun, max_bytes=0x22, eip=eip)
                #if quick_return is not None:
                #    self.lgr.debug('doX86 back from findReturnFromCall quick_return 0x%x' % quick_return)
                #else:
                #    self.lgr.debug('doX86 back from findReturnFromCall quick_return got None')


        if quick_return is None:
            ''' adjust first frame to have fun_addr and ret_addr '''
            pushed_bp = self.readAppPtr(bp)
            ret_to_addr = bp + self.mem_utils.wordSize(self.cpu)
            ret_to = self.readAppPtr(ret_to_addr)
            if not self.soMap.isCode(ret_to, self.pid):
                self.frames[0].ret_addr = None
            else:
                self.frames[0].ret_addr = ret_to
            self.frames[0].ret_to_addr = ret_to_addr
            self.frames[0].fun_addr = cur_fun
            self.frames[0].fun_name = cur_fun_name
            #if cur_fun is not None and ret_to is not None:
            #    self.lgr.debug('doX86, set frame 0 ret_to_addr 0x%x  ret_addr 0x%x  fun_addr 0x%x' % (ret_to_addr, ret_to, cur_fun))
            #else:
            #    self.lgr.debug('doX86, set frame 0 ret_to or cur_fun is None')
        
        #self.lgr.debug('doX86 enter loop. bp is 0x%x' % bp)
        ''' attempt to weed out bogus stack frames '''
        been_to_main = False
        while True:
            if bp == 0 and len(self.frames)>1:
                break
            pushed_bp = self.readAppPtr(bp)
            if pushed_bp == bp:
                #self.lgr.debug('stackTrace doX86, pushed bp same as bp, bail')
                break
            ret_to_addr = bp + self.mem_utils.wordSize(self.cpu)
            ret_to = self.readAppPtr(ret_to_addr)
            if ret_to is None:
                #self.lgr.debug('stackTrace doX86 ret_to None, bail')
                break
            if not self.soMap.isCode(ret_to, self.pid):
                #self.lgr.debug('stackTrace doX86 ret_to 0x%x is not code, bail' % ret_to)
                break

            ret_to_fname = self.soMap.getSOFile(ret_to)
            if was_clib and not resimUtils.isClib(ret_to_fname):
                #self.lgr.debug('stackTrace dox86 Was clib, now not, look for other returns? prev_sp is 0x%x bp is 0x%x, pushed_bp is 0x%x' % (prev_sp, bp, pushed_bp))
                max_bytes = bp - prev_sp
                other_ret_to = self.findReturnFromCall(prev_sp, cur_fun, max_bytes=max_bytes, eip=call_inst)
                #if other_ret_to is not None:
                #    self.lgr.debug('stackTrace dox86 found xtra stack frame')
                #else:
                #    self.lgr.debug('stackTrace dox86 found NO xtra stack frame')

            ws = self.mem_utils.wordSize(self.cpu)
            #self.lgr.debug('stackTrace doX86 pushed_bp was 0x%x ret_to is 0x%x, ret_to_addr was 0x%x bp was 0x%x ws %d was_clib? %r' % (pushed_bp, ret_to, ret_to_addr, bp, ws, was_clib))
            call_inst = self.followCall(ret_to)
            if call_inst is not None:
                added_frame = False
                #self.lgr.debug('stackTrace doX86 ret_to 0x%x followed call, call inst addr 0x%x' % (ret_to, call_inst))
                instruct = SIM_disassemble_address(self.cpu, call_inst, 1, 0)
                call_addr, fun_name = self.fun_mgr.getFunNameFromInstruction(instruct, call_inst)
                instruct_1 = self.fun_mgr.resolveCall(instruct, call_inst)
                fname = self.soMap.getSOFile(call_inst)
        
                #if call_addr is not None and been_to_main and not self.soMap.isMainText(call_addr):
                if call_addr is not None and been_to_main and not self.soMap.isAboveLibc(call_addr):
                    #self.lgr.debug('stackTrace doX86 been to main but now see lib? 0x%x bail' % call_addr)
                    ''' TBD hacky return value'''
                    bp = 0
                    break
                if call_addr is not None:
                     
                    #if cur_fun is not None:
                    #    self.lgr.debug('stackTrace x86 call addr 0x%x fun %s cur_fun: 0x%x' % (call_addr, fun_name, cur_fun))
                    #else:
                    #    self.lgr.debug('stackTrace x86 call addr 0x%x fun %s cur_fun is None' % (call_addr, fun_name))
                    #self.lgr.debug('stackTrace 8x86 pushed bp is 0x%x' % pushed_bp)
                    ''' TBD fix for windows '''
                    if not self.top.isWindows() and call_addr != cur_fun and quick_return is None:
                        #self.lgr.debug('stackTrace doX86 call findReturnFromCall')
                        ret_addr = self.findReturnFromCall(esp, cur_fun)
                        #if ret_addr is not None and self.soMap.isMainText(ret_addr):
                        if ret_addr is not None and self.soMap.isAboveLibc(ret_addr):
                             been_to_main = True
                        #self.lgr.debug('stackTrace doX86 back from findReturnFromCall')
                        if ret_addr is not None:
                            added_frame = True
                    else:
                        #if self.soMap.isMainText(call_addr):
                        if self.soMap.isAboveLibc(call_addr):
                             been_to_main = True
                    
                else:
                    #self.lgr.debug('stackTrace x86 no call_addr add frame add call_inst 0x%x  inst: %s fname %s' % (call_inst, instruct_1, fname)) 
                    was_clib = resimUtils.isClib(fname)
                    prev_sp = ret_to_addr - self.mem_utils.wordSize(self.cpu)
                    frame = self.FrameEntry(call_inst, fname, instruct_1, prev_sp, 
                        fun_name=fun_name, ret_addr=ret_to, ret_to_addr = ret_to_addr)
                    self.addFrame(frame)
                    #self.lgr.debug(frame.dumpString())
                    pass
                if self.fun_mgr is not None: 
                    cur_fun = self.fun_mgr.getFun(ret_to)
                bp = pushed_bp
                ''' only add if not done by findReturnFromCall'''
                if call_addr is not None and not added_frame:
                    #self.lgr.debug('stackTrace x86 add frame add call_inst 0x%x  inst: %s fname: %s' % (call_inst, instruct_1, fname)) 
                    was_clib = resimUtils.isClib(fname)
                    prev_sp = ret_to_addr - self.mem_utils.wordSize(self.cpu)
                    frame = self.FrameEntry(call_inst, fname, instruct_1, prev_sp, fun_addr=call_addr, 
                        fun_name=fun_name, ret_addr=ret_to, ret_to_addr = ret_to_addr)
                    self.addFrame(frame)
                    #self.lgr.debug(frame.dumpString())
            else:
                self.lgr.debug('stackTrace x86, no call_instr from ret_to 0x%x' % ret_to)
                break
        return bp
   
    def findReturnFromCall(self, ptr, cur_fun, max_bytes=900, eip=None):        
        ''' See if an x86 return instruction is within a max_bytes of the SP.  Handles clib cases where ebp is not pushed. 
            Likely more complicated then it needs to be.  Many special cases.'''
        got_fun_name = None
        cur_fun_name = None
        cur_is_clib = False
        if cur_fun is not None:
            cur_fun_name = self.fun_mgr.funFromAddr(cur_fun)
            #self.lgr.debug('stackTrace findReturnFromCall START ptr 0x%x cur_fun 0x%x (%s)' % (ptr, cur_fun, cur_fun_name))
            pass
        else:
            #self.lgr.debug('stackTrace findReturnFromCall START ptr 0x%x cur_fun NONE' % (ptr))
            pass
        esp = self.reg_frame['sp']
        current_instruct = None
        if eip is not None:
            current_instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)[1]
            #lib_file = self.top.getSO(eip)
            lib_file = self.soMap.getSOFile(eip)
            if resimUtils.isClib(lib_file):
                cur_is_clib = True
            #self.lgr.debug('stackTrace findReturnFromCall given eip 0x%x, is clib? %r for %s' % (eip, cur_is_clib, current_instruct))
        retval = None
        limit = ptr + max_bytes
        call_ip = None
        #while retval is None and ptr < limit:
        while ptr < limit:
            if retval is not None and call_ip is not None:
                if self.soMap.isAboveLibc(call_ip):
                    self.lgr.debug('stackTrace findReturnFromCall, call_ip is in main, we are done')
                    break
            val = self.readAppPtr(ptr)
            if val is None:
                self.lgr.debug('stackTrace findReturnFromCall, failed to read from 0x%x' % ptr)
                ptr = ptr + self.mem_utils.wordSize(self.cpu)
                done = True
                continue
            # TBD should be part of readPtr?
            if self.mem_utils.wordSize(self.cpu) == 8:
                val = val & 0x0000ffffffffffff
            skip_this = False
            if val == 0:
                ptr = ptr + self.mem_utils.wordSize(self.cpu)
                #self.lgr.debug('val read from 0x%x is zero, continue' % ptr)
                continue
            #self.lgr.debug('findReturnFromCall ptr 0x%x val 0x%x  limit 0x%x' % (ptr, val, limit))    
            if self.soMap.isCode(val, self.pid):
                #self.lgr.debug('findReturnFromCall is code val 0x%x ptr was 0x%x' % (val, ptr))
                call_ip = self.followCall(val)
                if call_ip is not None:
                    fname = self.soMap.getSOFile(call_ip)
                    if cur_fun is None and self.fun_mgr is not None:
                        cur_fun = self.fun_mgr.getFun(call_ip)
                        #if cur_fun is not None:
                        #    self.lgr.debug('findReturn had no cur_fun, set to 0x%x' % cur_fun)
                        #    pass
                        #else:
                        #    self.lgr.debug('findReturn, still no curfun call_ip was 0x%x' % call_ip)
                        #    pass
                    instruct_of_call = SIM_disassemble_address(self.cpu, call_ip, 1, 0)
                    instruct = instruct_of_call[1]
                    #self.lgr.debug('findRetrunFromCall call_ip 0x%x  %s' % (call_ip, instruct))
                    call_addr, fun_name = self.fun_mgr.getFunNameFromInstruction(instruct_of_call, call_ip)
                    #if call_addr is not None:
                    #    if cur_fun is not None:
                    #        self.lgr.debug('findReturnFromCall call_addr 0x%x cur_fun 0x%x fun_name %s cur_fun_name %s' % (call_addr, cur_fun, fun_name, cur_fun_name))
                    #    else:
                    #        self.lgr.debug('findReturnFromCall call_addr 0x%x cur_fun none fun_name %s cur_fun_name %s' % (call_addr, fun_name, cur_fun_name))
                    if call_addr == cur_fun or self.sameFun(fun_name, cur_fun_name):
                        if fun_name is not None:
                            instruct = '%s %s' % (self.callmn, fun_name)
                        frame = self.FrameEntry(call_ip, fname, instruct, ptr, fun_addr=call_addr, fun_name=fun_name, ret_to_addr=ptr)
                        frame.ret_addr = call_ip + instruct_of_call[0] 
                        self.addFrame(frame)
                        retval = self.readAppPtr(ptr)
                        #self.lgr.debug('findReturnFromCall xx Found x86 call to %s instruct:%s  ret_to_addr 0x%x ret 0x%x add frame' % (cur_fun, instruct, ptr, retval))
                    elif call_addr is None:
                        frame = self.FrameEntry(call_ip, fname, instruct, ptr, ret_to_addr=ptr)
                        frame.ret_addr = call_ip + instruct_of_call[0] 
                        self.addFrame(frame)
                        retval = self.readAppPtr(ptr)
                        #self.lgr.debug('findReturnFromCall no call_addr found x86 call instruct:%s  ret_to_addr 0x%x ret 0x%x add frame' % (instruct, ptr, retval))
                    elif self.fun_mgr.isRelocate(call_addr):
                        #self.lgr.debug('findReturnFromCall 0x%x is relocate')
                        #new_call_addr, fun_name = self.fun_mgr.getFunNameFromInstruction(instruct, call_addr)
                        instruct = '%s %s' % (self.callmn, fun_name)
                        frame = self.FrameEntry(call_ip, fname, instruct, ptr, fun_addr=call_addr, fun_name=fun_name, ret_to_addr=ptr)
                        frame.ret_addr = call_ip + instruct_of_call[0] 
                        self.addFrame(frame)
                        #self.lgr.debug('relocated frame is %s' % frame.dumpString())
                        retval = self.readAppPtr(ptr)
                    elif (fun_name is not None and fun_name.startswith('memcpy')) and (current_instruct is not None and current_instruct.startswith('rep movsd')):
                        # hacks are us
                        frame = self.FrameEntry(call_ip, fname, instruct, ptr, fun_addr=call_addr, fun_name=fun_name, ret_to_addr=ptr)
                        frame.ret_addr = call_ip + instruct_of_call[0] 
                        self.addFrame(frame)
                        retval = self.readAppPtr(ptr)
                        #self.lgr.debug('memcpy/rep x86 mov hack call %s ret_t_addr: 0x%x ret: 0x%x' % (instruct, ptr, retval))
                    else:
                        ''' look for GOTish jump to dword '''
                        retval = self.isGOT(ptr, call_addr, cur_fun, cur_fun_name, instruct_of_call, call_ip, fname, cur_is_clib)
                #else:
                #    self.lgr.debug('call_ip is None')
            ptr = ptr + self.mem_utils.wordSize(self.cpu)
        #if ptr >= limit:
        #    self.lgr.debug('findReturnFromCall hit stack limit of 0x%x' % limit)
        return retval                

    def isGOT(self, ptr, call_addr, cur_fun, cur_fun_name, instruct_of_call, call_ip, fname, cur_is_clib):
        retval = None
        first_instruct = SIM_disassemble_address(self.cpu, call_addr, 1, 0)
        #self.lgr.debug('stackTrace isGOT first_instruct is %s' % first_instruct[1])
        if first_instruct[1].lower().startswith('jmp dword'):
            fun_name = None
            new_call_addr, fun_name = self.fun_mgr.getFunNameFromInstruction(first_instruct, call_addr)
            if new_call_addr is not None:
                instruct = '%s %s' % (self.callmn, fun_name)
                call_addr = new_call_addr
                self.lgr.debug('is jmp, call_addr now 0x%x' % call_addr)
                got_fun_name = self.fun_mgr.funFromAddr(call_addr)
                if got_fun_name is None:
                    got_entry = self.readAppPtr(call_addr)
                    got_fun_name = self.fun_mgr.funFromAddr(got_entry)
                    self.lgr.debug('stackTrace isGOT got go again fun %s' % got_fun_name)
                else:
                    self.lgr.debug('stackTrace isGOT got fun %s' % got_fun_name)
                    pass
                instruct = self.fun_mgr.resolveCall(instruct_of_call, call_addr)
                if call_addr == cur_fun:
                    frame = self.FrameEntry(call_ip, fname, instruct, ptr, fun_addr=call_addr, fun_name=fun_name, ret_to_addr=ptr)
                    frame.ret_addr = call_ip + instruct_of_call[0] 
                    self.addFrame(frame)
                    retval = self.readAppPtr(ptr)
                    self.lgr.debug('stackTrace isGOT Found x86 call %s  ret_to_addr 0x%x ret 0x%x add frame' % (instruct, ptr, retval))
                elif cur_fun_name is not None and got_fun_name is not None and got_fun_name.startswith(cur_fun_name):
                    frame = self.FrameEntry(call_ip, fname, instruct, ptr, fun_addr=call_addr, fun_name=cur_fun_name, ret_to_addr=ptr)
                    frame.ret_addr = call_ip + instruct_of_call[0] 
                    self.addFrame(frame)
                    retval = self.readAppPtr(ptr)
                    self.lgr.debug('stackTrace isGOT Found GOT x86 call %s  is got %s   add entry  call_ip 0x%x  call_addr: 0x%x ret_to_addr: 0x%x ret: 0x%x add frame' % (instruct, got_fun_name, call_ip, call_addr, ptr, retval))
                elif got_fun_name is not None and cur_is_clib:
                    frame = self.FrameEntry(call_ip, fname, instruct, ptr, fun_addr=call_addr, fun_name=got_fun_name, ret_to_addr=ptr)
                    frame.ret_addr = call_ip + instruct_of_call[0] 
                    self.addFrame(frame)
                    retval = self.readAppPtr(ptr)
                    self.lgr.debug('stackTrace isGOT Found x86 GOT, though no current fuction found. call %s  is got %s   add frame  call_ip 0x%x  call_addr: 0x%x ret_to_addr: 0x%x ret: 0x%x' % (instruct, 
                         got_fun_name, call_ip, call_addr, ptr, retval))
                elif got_fun_name is not None:
                    frame = self.FrameEntry(call_ip, fname, instruct, ptr, fun_addr=call_addr, fun_name=got_fun_name, ret_to_addr=ptr)
                    frame.ret_addr = call_ip + instruct_of_call[0] 
                    self.addFrame(frame)
                    retval = self.readAppPtr(ptr)
                    self.lgr.debug('stackTrace isGOT Found x86 GOT, though current fuction is not called function. call %s  is got %s   add entry  call_ip 0x%x  call_addr: 0x%x ret_to_addr: 0x%x ret: 0x%x' % (instruct, 
                         got_fun_name, call_ip, call_addr, ptr, retval))
            else:
                self.lgr.debug('stackTrace isGOT call_addr is none from %s' % (first_instruct[1]))
        return retval

    def sameFun(self, fun1, fun2):
        retval = False
        pile1 = ['strcmp', 'wcscmp', 'mbscmp', 'mbscmp_l']
        if fun1 in pile1 and fun2 in pile1:
            retval = True
        return retval
 

    def getCallTo(self, call_ip): 
        instruct = SIM_disassemble_address(self.cpu, call_ip, 1, 0)[1]
        call_to_s = instruct.split()[1]
        call_to = None
        #self.lgr.debug('stackTrace check call to %s' % call_to_s)
        try:
            call_to = int(call_to_s, 16)
        except:
            pass 
        return call_to

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
        #if self.stack_base is not None:
        #    self.lgr.debug('stackTrace doTrace pid:%d esp is 0x%x eip 0x%x  stack_base 0x%x' % (self.pid, esp, eip, self.stack_base))
        #    pass
        #else:
        #    self.lgr.debug('stackTrace doTrace NO STACK BASE pid:%d esp is 0x%x eip 0x%x' % (self.pid, esp, eip))
        #    pass
        done  = False
        count = 0
        #ptr = ebp
        ptr = esp
        been_in_main = False
        prev_ip = None
        #if self.soMap.isMainText(eip):
        if self.soMap.isAboveLibc(eip):
            been_in_main = True
            if self.cpu.architecture != 'arm' or not self.soMap.isMainText(self.reg_frame['lr']):
                self.lgr.debug('stackTrace starting in main with lr that is not above libc, text set prev_ip to 0x%x' %eip)
                prev_ip = eip
        #prev_ip = eip
        if self.fun_mgr is None:
            self.lgr.warning('stackTrace has no ida functions')

        ''' record info about current IP '''
       
        instruct_tuple = SIM_disassemble_address(self.cpu, eip, 1, 0)
        instruct = instruct_tuple[1]
        fname = self.soMap.getSOFile(eip)
        prev_fname = fname
        instruct = self.fun_mgr.resolveCall(instruct_tuple, eip)

        #self.lgr.debug('StackTrace doTrace xx begin pid:%d cur eip 0x%x instruct %s  fname %s' % (self.pid, eip, instruct, fname))
        if fname is None:
            frame = self.FrameEntry(eip, 'unknown', instruct, esp)
            self.addFrame(frame)
        else:
            frame = self.FrameEntry(eip, fname, instruct, esp)
            self.addFrame(frame)
        #self.lgr.debug('first add frame %s' % frame.dumpString())
        ''' TBD *********** DOES this prev_ip assignment break frames that start in libs? '''
        if prev_ip is None and self.cpu.architecture == 'arm':
            prev_ip = self.isCallToMe(fname, eip)
            #if prev_ip is not None:
            #    self.lgr.debug('doTrace back from isCallToMe prev_ip set to 0x%x' % prev_ip)
            #else:
            #    self.lgr.debug('doTrace back from isCallToMe prev_ip None, must not be call to me')
        
        cur_fun = None
        cur_fun_name = None
        if self.fun_mgr is not None:
            cur_fun = self.fun_mgr.getFun(eip)
            if prev_ip == None and cur_fun is not None:
                cur_fun_name = self.fun_mgr.getFunName(cur_fun)
                if cur_fun_name is None:
                    #self.lgr.debug('stackTrace fun_mgr.getFunName returned none for cur_fun 0x%x' % cur_fun) 
                    pass
                elif cur_fun_name.startswith('.'):
                    cur_fun_name = cur_fun_name[1:]
                elif cur_fun_name.startswith('_'):
                    cur_fun_name = cur_fun_name[1:]
                #self.lgr.debug('doTrace starting eip: 0x%x is in fun %s 0x%x' % (eip, cur_fun_name, cur_fun))

        if self.cpu.architecture != 'arm':
            bp = self.doX86()
            if bp == 0 and len(self.frames)>1:
                ''' walked full stack '''
                #self.lgr.debug('doTrace starting doX86 got it, we are done')
                done = True
            else:
                #self.lgr.debug('stackTrace doTrace after doX86 bp 0x%x num frames %s' % (bp, len(self.frames)))
                if len(self.frames) > 5:
                    ''' TBD revisit this wag '''
                    done = True

        while not done and (count < 9000): 
            ''' ptr iterates through stack addresses.  val is the value at that address '''
            val = self.readAppPtr(ptr)
            if val is None:
                #self.lgr.debug('stackTrace, failed to read from 0x%x' % ptr)
                count += 1
                ptr = ptr + self.mem_utils.wordSize(self.cpu)
                done = True
                continue
            # TBD should be part of readPtr?
            if self.mem_utils.wordSize(self.cpu) == 8:
                val = val & 0x0000ffffffffffff
            skip_this = False
            if val == 0:
                count += 1
                ptr = ptr + self.mem_utils.wordSize(self.cpu)
                continue
            #self.lgr.debug('ptr 0x%x val 0x%x' % (ptr, val))    
            if self.soMap.isCode(val, self.pid):
                call_ip = self.followCall(val)
                #if call_ip is not None:
                #   self.lgr.debug('is code: 0x%x from ptr 0x%x   PC of call is 0x%x' % (val, ptr, call_ip))
                #   pass
                #else:
                #   self.lgr.debug('is code not follow call: 0x%x from ptr 0x%x   ' % (val, ptr))
                #   pass
                   
                if been_in_main and not self.soMap.isMainText(val):
                    ''' once in main text assume we never leave? what about callbacks?'''
                    skip_this = True
                    
                if been_in_main and self.fun_mgr is not None and call_ip is not None and prev_ip is not None:
                #if self.ida_funs is not None and call_ip is not None and prev_ip is not None:
                    call_to = self.getCallTo(call_ip)
                    if call_to is not None:
                        #self.lgr.debug('stackTrace call_to 0x%x ' % call_to)
                        if not self.fun_mgr.soChecked(call_to):
                            ''' should we add ida function analysys? '''
                            if not self.fun_mgr.isFun(call_to):
                                fname, start, end = self.soMap.getSOInfo(call_to)
                                #self.lgr.debug('stackTrace so check of %s the call_to of 0x%x not in IDA funs?' % (fname, call_to))
                                if fname is not None:
                                    full_path = self.targetFS.getFull(fname, self.lgr)
                                    self.fun_mgr.add(full_path, start)
                            self.fun_mgr.soCheckAdd(call_to) 
                        if self.fun_mgr.isFun(call_to):
                            if not self.fun_mgr.inFun(prev_ip, call_to):
                                first_instruct = SIM_disassemble_address(self.cpu, call_to, 1, 0)
                                #self.lgr.debug('first_instruct is %s' % first_instruct[1])
                                if self.cpu.architecture == 'arm' and first_instruct[1].lower().startswith('b '):
                                    fun_hex, fun = self.fun_mgr.getFunNameFromInstruction(first_instruct, call_to)
                                    #self.lgr.debug('direct branch 0x%x %s' % (fun_hex, fun))
                                    if not (self.fun_mgr.isFun(fun_hex) and self.fun_mgr.inFun(prev_ip, fun_hex)):
                                        skip_this = True
                                        #self.lgr.debug('StackTrace addr (prev_ip) 0x%x not in fun 0x%x, or just branch 0x%x skip it' % (prev_ip, call_to, fun_hex))
                                    else:
                                        ''' record the direct branch, e.g., B fuFun '''
                                        frame = self.FrameEntry(call_to, fname, first_instruct[1], ptr, fun_addr=fun_hex, fun_name=fun)
                                        #self.lgr.debug('stackTrace direct branch fname: %s add frame %s' % (fname, frame.dumpString()))
                                        self.addFrame(frame)
                                elif self.cpu.architecture != 'arm':
                                    if first_instruct[1].lower().startswith('jmp dword'):
                                        fun_hex, fun = self.fun_mgr.getFunNameFromInstruction(first_instruct, call_to)
                                        if not (self.fun_mgr.isFun(fun_hex) and self.fun_mgr.inFun(prev_ip, fun_hex)):
                                            skip_this = True
                                            #self.lgr.debug('StackTrace addr (prev_ip) 0x%x not in fun 0x%x, or just branch 0x%x skip it' % (prev_ip, call_to, fun_hex))
                                        else:
                                            ''' record the direct branch, e.g., jmp dword...'''
                                            frame = self.FrameEntry(call_to, fname, first_instruct[1], ptr, fun_addr=fun_hex, fun_name=fun)
                                            #self.lgr.debug('stackTrace direct branch fname: %s add frame %s' % (fname, frame.dumpString()))
                                            self.addFrame(frame)
                                    else:
                                        bp = self.mem_utils.getRegValue(self.cpu, 'ebp')
                                        if (bp + self.mem_utils.wordSize(self.cpu)) != ptr:
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
                            elif self.fun_mgr.isRelocate(call_to):
                                #self.lgr.debug('stackTrace 0x%x is relocatable, but already in main text, assume noise and skip' % call_to)
                                skip_this = True
                            else:
                                #self.lgr.debug('stackTrace 0x%x is not a function?' % call_to)
                                pass
                ''' The block above assumes we've been in main.  TBD clean it up.''' 
                if call_ip is not None and not skip_this:
                    skip_this = False
                    instruct = SIM_disassemble_address(self.cpu, call_ip, 1, 0)
                    fun_addr = None 
                    fun_name = None 
                    instruct_str = instruct[1]
                    if instruct_str.startswith(self.callmn):
                        fun_hex, fun = self.fun_mgr.getFunNameFromInstruction(instruct, call_ip)
                        #self.lgr.debug('StackTrace clean this up, got fun %s' % fun)
                        if prev_ip is not None:
                            cur_fun_name = self.fun_mgr.getFunName(prev_ip)
                            #self.lgr.debug('StackTrace prev_ip 0x%x, fun %s' % (prev_ip, cur_fun_name))
                        if fun is not None:
                            if cur_fun_name is not None:
                                if not self.funMatch(fun, cur_fun_name): 
                                    if self.cpu.architecture != 'arm':
                                        bp = self.mem_utils.getRegValue(self.cpu, 'ebp')
                                        if (bp + self.mem_utils.wordSize(self.cpu)) != ptr:
                                            #self.lgr.debug('StackTrace candidate <%s> does not match <%s> and bp is 0x%x and  ptr is 0x%x skip it' % (fun, cur_fun_name, bp, ptr))
                                            count += 1
                                            ptr = ptr + self.mem_utils.wordSize(self.cpu)
                                            cur_fun_name = None
                                            continue
                                        else:
                                            cur_fun_name = None
                                    else:
                                        #self.lgr.debug('stackTrace candidate function %s does not match current function %s, skipit' % (fun, cur_fun_name))
                                        ''' don't count this against max frames '''
                                        count += 1
                                        ptr = ptr + self.mem_utils.wordSize(self.cpu)
                                        ''' TBD broken hueristic, e.g., sscanf calls strlen. hack for now... '''
                                        cur_fun_name = None
                                        continue
                                else:
                                    ''' first frame matches expected function '''
                                    cur_fun_name = None
                                instruct_str = '%s   %s' % (self.callmn, fun)
                                #self.lgr.debug('StackTrace instruct_str set to %s' % instruct_str)
                            else:
                                instruct_str = '%s   %s' % (self.callmn, fun)
                                #self.lgr.debug('StackTrace no cur_fun_name, instruct_str set to %s' % instruct_str)
                        else:
                            #self.lgr.debug('stackTrace fun was None from instruct %s' % instruct[1])
                            pass
                        if fun_hex is not None:
                            #self.lgr.debug('stackTrace fun_hex 0x%x, fun %s instr %s' % (fun_hex, fun, instruct_str))
                            ''' TBD fix for windows '''
                            if not self.top.isWindows():
                                self.soCheck(fun_hex)
                        else:
                            if prev_ip is not None and self.fun_mgr is not None:
                                fun_hex = self.fun_mgr.getFun(prev_ip)
                                if fun_hex is not None:
                                    fun = self.fun_mgr.getFunName(fun_hex)
                                    #self.lgr.debug('stackTrace fun_hex hacked to 0x%x using prev_ip and fun to %s.  TBD generalize this' % (fun_hex, fun))
                                    instruct_str = '%s   %s' % (self.callmn, fun)

                                    pass

                                
                        #self.lgr.debug('ADD STACK FRAME FOR 0x%x %s  ptr 0x%x.  prev_ip will become 0x%x' % (call_ip, instruct_str, ptr, call_ip))
                        fname = self.soMap.getSOFile(val)
                        if fname is None:
                            #print('0x%08x  %-s' % (call_ip, 'unknown'))
                            frame = self.FrameEntry(call_ip, 'unknown', instruct_str, ptr, fun_addr=fun_hex, fun_name=fun)
                            self.addFrame(frame)
                            #self.lgr.debug('stackTrace fname none add frame %s' % frame.dumpString())
                        else:
                            ''' ad-hoc detect clib ghost frames, assume clib does not call other libraries.  exceptions?  TBD '''
                            #if fname.startswith('clib'):
                            #    if not prev_fname.startswith('clib') and not prev_fname.startswith('libpthread'):
                            #        #self.lgr.debug('stackTrace found call from clib to 0x%x, assume a ghost frame')
                            #        skip_this = True        
                            if prev_ip is not None and self.soMap.isMainText(val):
                                if not self.soMap.isMainText(prev_ip):
                                    #self.lgr.debug('stackTrace val 0x%x in main (%s), prev 0x%x (%s) was not' % (val, fname, prev_ip, prev_fname))
                                    call_to = self.getCallTo(call_ip)
                                    if call_to is not None:
                                        if self.soMap.isMainText(call_to):
                                            #self.lgr.debug('stackTrace prev stack frame was a lib, but we called into main.  If not a PLT, then bail. call-to is 0x%x' % call_to)
                                            if not self.fun_mgr.isRelocate(call_to) and not self.isPLT(call_to):
                                                skip_this = True
                                                #self.lgr.debug('stackTrace not a PLT, skipped it first_instruct %s' % first_instruct[1])

                            if not skip_this:
                                if self.cpu.architecture == 'arm':
                                    ret_addr = call_ip + 4
                                    frame = self.FrameEntry(call_ip, fname, instruct_str, ptr, fun_addr=fun_hex, fun_name=fun, ret_addr=ret_addr)
                                else:
                                    #self.lgr.warning('stackTrace NOT setting ret_addr for x86, TBD')
                                    frame = self.FrameEntry(call_ip, fname, instruct_str, ptr, fun_addr=fun_hex, fun_name=fun)
                                self.addFrame(frame)
                                #self.lgr.debug('stackTrace fname %s fun is %s add frame %s' % (fname, fun, frame.dumpString()))
                            else:
                                pass
                                #self.lgr.debug('stackTrace told to skip %s' % frame.dumpString())
                        if not skip_this:
                            prev_fname = fname
                            prev_ip = call_ip
                            if self.soMap.isAboveLibc(call_ip):
                                been_in_main = True
                                #self.lgr.debug('stackTrace been in main')
                    else:
                        #self.lgr.debug('doTrace not a call? %s' % instruct_str)
                        frame = self.FrameEntry(call_ip, fname, instruct_str, ptr, None, None)
                        self.addFrame(frame)
                        #self.lgr.debug('stackTrace not a call? %s fname %s, add frame %s' % (instruct_str, fname, frame.dumpString()))
                else:
                    #self.lgr.debug('nothing from followCall')
                    pass
            elif val is not None and val != 0:
                #self.lgr.debug('ptr 0x%x not code 0x%x' % (ptr, val))
                pass
            count += 1
            ptr = ptr + self.mem_utils.wordSize(self.cpu)
            if self.stack_base is not None and ptr > self.stack_base:
                #self.lgr.debug('stackTrace ptr 0x%x > stack_base 0x%x' % (ptr, self.stack_base)) 
                done = True
            elif self.max_frames is not None and len(self.frames)>= self.max_frames:
                #self.lgr.debug('stackFrames got max frames, done max is %d, got %d' % (self.max_frames, len(self.frames)))
                done = True
            elif self.max_bytes is not None and count > self.max_bytes:
                #self.lgr.debug('stackFrames got max bytes %d, done' % self.max_bytes)
                done = True

    def isPLT(self, eip):
        # TBD replace this ad hoc hack with analysis output telling us where the PLT is
        retval = False
        first_instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        if first_instruct[1].startswith('jmp'):
            retval = True
        elif first_instruct[1].startswith('add') and 'pc' in first_instruct[1]:
            retval = True
        return retval

    def soCheck(self, eip):
                
        if not self.fun_mgr.soChecked(eip):
            ''' should we add ida function analysis? '''
            if self.fun_mgr is not None and not self.fun_mgr.isFun(eip):
                fname, start, end = self.soMap.getSOInfo(eip)
                if fname is not None:
                    #full = self.targetFS.getFull(fname, self.lgr)
                    full = self.top.getAnalysisPath(fname)
                    self.lgr.debug('stackTrace soCheck eip 0x%x not a fun? Adding it.  fname %s full %s start 0x%x' % (eip, fname,full, start))
                    self.fun_mgr.add(full, start)
            self.fun_mgr.soCheckAdd(eip) 

    def countFrames(self):
        return len(self.frames)

    def addFrame(self, frame):
        prev_ip = None
        if len(self.frames) > 0:
            prev_ip = self.frames[-1].ip
        if frame.ip != prev_ip:
            if self.fun_mgr is not None:
                fun_of_ip = self.fun_mgr.getFunName(frame.ip)
                frame.fun_of_ip = fun_of_ip
                #self.lgr.debug('stackTrace addFrame set fun_of_ip to %s frame.ip 0x%x' % (fun_of_ip, frame.ip))
            self.frames.append(frame)
        else:
            #self.lgr.debug('stackTrace skipping back to back identical calls: %s' % frame.instruct)
            pass
       
    def readAppPtr(self, addr):
        if self.word_size == 4: 
            retval = self.mem_utils.readWord32(self.cpu, addr)
        else:
            retval = self.mem_utils.readWord(self.cpu, addr)
        return retval
