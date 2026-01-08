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
'''
Generate a stack frame trace.  Or try to.
'''
from simics import *
import json
import os
import memUtils
import decode
import decodeArm
import decodePPC32
import resimUtils
import ntpath
import dataWatch
''' Note, clibFuns also cleans up function names.  However it alters names
    for the convenience of dataWatch.  TBD add an option to clibFuns to clean
    up prefix/suffix noise without altering the function name.
'''
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
            ''' name of fuction containing the ip '''
            self.fun_of_ip = None
            ''' address of fuction containing the ip '''
            self.fun_addr_of_ip = None
            ''' arm lr return value '''
            self.lr_return = lr_return
            ''' where the ret_addr was read from '''
            self.ret_to_addr = ret_to_addr
        def dumpString(self):
            if self.fun_addr is None:
                fun_addr = 'fun_addr: None'
            else:
                fun_addr = 'fun_addr: 0x%x' % self.fun_addr
            if self.ret_addr is not None:
                return 'ip: 0x%x fname: %s instruct: %s sp: 0x%x %s ret_addr: 0x%x fun_of_ip %s' % (self.ip, self.fname, self.instruct, self.sp, fun_addr, self.ret_addr, self.fun_of_ip)
            else:
                return 'ip: 0x%x fname: %s instruct: %s sp: 0x%x %s fun_of_ip %s' % (self.ip, self.fname, self.instruct, self.sp, fun_addr, self.fun_of_ip)

    def __init__(self, top, cpu, tid, soMap, mem_utils, task_utils, stack_base, fun_mgr, targetFS, 
                 reg_frame, disassembler, lgr, max_frames=None, max_bytes=None, skip_recurse=False, stop_after_clib=False, use_bp=True):
        self.top = top
        self.cpu = cpu
        if self.cpu.architecture in ['arm', 'arm64']:
            self.decode = decodeArm
        if self.cpu.architecture in ['ppc32']:
            self.decode = decodePPC32
        else:
            self.decode = decode
        self.tid = tid
        self.word_size = soMap.wordSize(tid)
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
        self.skip_recurse = skip_recurse
        self.disassembler = disassembler
        self.stop_after_clib = stop_after_clib
        self.use_bp = use_bp
        ''' limit how far down the stack we look for calls '''
        self.max_bytes = max_bytes 
        if cpu.architecture in ['arm', 'arm64']:
            self.callmn = 'bl'
        elif cpu.architecture == 'ppc32':
            self.callmn = 'bl'
        else:
            self.callmn = 'call'

        if tid == 0:
            lgr.error('stackTrace asked to trace tid 0?')
            return

        if tid == 0:
            lgr.error('stackTrace asked to trace tid 0?')
            return

        self.prev_frame_sp = None
        self.mind_the_gap = False
        self.black_list = []
        self.gap_reset_to = 1
        self.most_frames = 0
        self.best_frames = []
        # for tracking ppc bctrl instructions
        self.recent_bctrl = None
        cur_eip = self.top.getEIP(cpu=cpu)
        if self.mem_utils.isKernel(cur_eip):
            self.lgr.error('stackTrace called from within kernel.  No support for that yet.')
        else:
            self.doTrace()

    def isCall(self, instruct):
        mn = self.decode.getMn(instruct)
        retval = False
        if self.cpu.architecture in ['arm', 'arm64']:
            if mn.startswith('bl'):
                retval = True
        elif self.cpu.architecture in ['ppc32']:
            if mn == 'bl':
                retval = True
            elif mn == 'bctrl':
                self.lgr.debug('stackTrace got bctrl')
                retval = True
        else:
            if mn == 'call':
                retval = True
        return retval

    def isJmp(self, instruct):
        mn = self.decode.getMn(instruct[1])
        retval = False
        if self.cpu.architecture in ['arm', 'arm64']:
            if mn in ['b', 'bx']:
                retval = True
        elif self.cpu.architecture in ['ppc32']:
            if mn == 'b':
                retval = True
        else:
            if mn.startswith('j'):
                retval = True
        return retval
            
    def followCall(self, return_to):
        ''' given a returned to address, look backward for the address of the call instruction '''
        retval = None
        if return_to <= 10 or not self.soMap.isCode(return_to, self.tid):
            #self.lgr.debug('stackTrace followCall 0x%x not code?' % return_to)
            return None
        if self.cpu.architecture in ['arm', 'arm64', 'ppc32']:
            #self.lgr.debug('followCall return_to 0x%x' % return_to)
            eip = return_to - 4
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            #self.lgr.debug('followCall instruct is %s' % instruct[1])
            #if self.decode.isCall(self.cpu, instruct[1], ignore_flags=True):
            if self.isCall(instruct[1]):
                if self.cpu.architecture == 'ppc32' and instruct[1].startswith('bctrl'):
                    self.recent_bctrl = eip
                    self.lgr.debug('stackTrace followCall is bctrl at 0x%x' % (eip))
                retval = eip
        else:
            fun_addr = self.fun_mgr.getFun(return_to)
            #self.lgr.debug('stackTrace followCall return_to 0x%x' % return_to)
            if fun_addr is not None:
                retval = self.disassembler.getPrevInstruction(return_to, fun_addr)
                #self.lgr.debug('stackTrace followCall return_to 0x%x back from disassembler with %s' % (return_to, retval))
            else:
                eip = return_to - 2
                #self.lgr.debug('followCall no function found for return_to is 0x%x  ip 0x%x' % (return_to, eip))
                # TBD use instruction length to confirm it is a true call
                # not always 2* word size?
                count = 0
                while retval is None and count < 4*self.mem_utils.wordSize(self.cpu) and eip>0:
                    instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                    #self.lgr.debug('stackTrace followCall count %d eip 0x%x instruct %s len %d' % (count, eip, instruct[1], instruct[0]))
                    # TBD hack.  Fix this by getting bb start and walking forward? only if we have the analysis. if not then rely on hack. 
                    if self.isCall(instruct[1]) and 'call far ' not in instruct[1] and (eip + instruct[0]) == return_to:
                        parts = instruct[1].split()
                        if len(parts) == 2:
                            if self.decode.isReg(parts[1]):
                                reg_size = self.decode.regLen(parts[1])
                                #self.lgr.debug('stackTrace followCall eip: 0x%x reg is %s word size %d reg size %d' % (eip, parts[1], self.word_size, reg_size))
                                if reg_size == self.word_size:
                                    retval = eip
                                    break
                                else:
                                    #self.lgr.debug('stackTrace followCall word size %d but reg size %d, IGNORE' % (self.word_size, reg_size))
                                    eip = eip-1
                            else:
                                try:
                                    dst = int(parts[1],16)
                                except:
                                    retval = eip
                                    # TBD break or continue?
                                    continue
                                if self.soMap.isCode(dst, self.tid):
                                    retval = eip
                                    break 
                                else:
                                    self.lgr.debug('stackTrace dst not code 0x%x' % dst)
                                    eip = eip-1
                        else:        
                            retval = eip
                            break 
                    elif 'illegal memory mapping' in instruct[1]:
                        break
                    else:
                        eip = eip-1
                    count = count+1
                # end while
            #if retval is not None:
            #    self.lgr.debug('followCall return 0x%x' % retval)
        return retval

    def getJson(self):
        retval = []
        for frame in self.frames:
            item = {}
            item['ip'] = frame.ip
            if self.top.isWindows():
                fname = ntpath.basename(frame.fname)
            else:
                fname = os.path.basename(frame.fname)
            item['fname'] = fname
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
                if self.top.isWindows():
                    fname = ntpath.basename(frame.fname)
                else:
                    fname = os.path.basename(frame.fname)
            else:
                fname = 'unknown'
            sp_string = ''
            if verbose:
                sp_string = ' sp: 0x%x' % frame.sp
            if frame.fun_of_ip is None:
                fun_of_ip = None
            else:
                fun_of_ip = frame.fun_of_ip
            if fun_of_ip is None and self.fun_mgr is not None:
                fun_of_ip = self.fun_mgr.getFunName(frame.ip)
              
            if fun_of_ip is not None:
                fun_of_ip = cppClean(fun_of_ip)
            if fun_of_ip is not None: 
                print('%s 0x%08x %s %s %s' % (sp_string, frame.ip, frame.fname, frame.instruct, fun_of_ip))
            else:
                print('%s 0x%08x %s %s' % (sp_string, frame.ip, frame.fname, frame.instruct))


    def isCallToMe(self, fname, eip, ptr):
        ''' if LR looks like a call to current function, add frame. Returns lr and stack adjust if frame is added. '''
        retval = (None, None)
        if self.cpu.architecture in ['arm', 'arm64', 'ppc32']:
            ''' macro-type calls, e.g., memset don't bother with stack frame return value? '''
            '''
            cpl = memUtils.getCPL(self.cpu)
            if cpl == 0:
                lr = self.mem_utils.getRegValue(self.cpu, 'lr_usr')
            else:
                lr = self.mem_utils.getRegValue(self.cpu, 'lr')
            '''
            lr = self.reg_frame['lr']
            #ptr = self.reg_frame['sp']
            ''' TBD also for 64-bit? '''
            call_instr = lr-4
            #self.lgr.debug("isCallToMe lr was 0x%x call_instr 0x%x  eip 0x%x" % (lr, call_instr, eip))
            fun_name = None
            if self.fun_mgr is not None:
                cur_fun = self.fun_mgr.getFun(eip)
                if cur_fun is not None:
                    fun_name = self.fun_mgr.getFunName(cur_fun)
                    #self.lgr.debug('isCallToMe eip: 0x%x is in cur fun %s 0x%x' % (eip, fun_name, cur_fun))
                # Name of the function we'd return to via LR
                ret_to = self.fun_mgr.getFun(lr)
                #if ret_to is None:
                #    self.lgr.debug('isCallToMe lr of 0x%x is not a fun?' % lr)
                #if cur_fun is not None and ret_to is not None:
                #    self.lgr.debug('isCallToMe eip: 0x%x (cur_fun 0x%x) lr 0x%x (ret_to fun 0x%x) ' % (eip, cur_fun, lr, ret_to))
                #    pass
                if cur_fun == ret_to and self.cpu.architecture == 'ppc32':
                    lr = self.mem_utils.getRegValue(self.cpu, 'r0')
                    ret_to = self.fun_mgr.getFun(lr)
                    self.lgr.debug('stackTrace isCallToMe lr was current function, try r0 0x%x' % lr) 
                if cur_fun != ret_to:
                    try:
                        instruct = SIM_disassemble_address(self.cpu, call_instr, 1, 0)
                    except OverflowError:
                        self.lgr.debug('stackTrace isCallToMe could not get instruct from 0x%x' % call_instr)
                        return retval 
                    if self.isCall(instruct[1]):
                        fun_hex, fun = self.fun_mgr.getFunNameFromInstruction(instruct, call_instr)
                        op2, op1 = self.decode.getOperands(instruct[1])
                        #if fun_hex is None:
                        #    self.lgr.debug('stackTrace isCallToMe fun_hex was None for instruct %s at 0x%x' % (instruct[1], call_instr))
                        #    pass
                        #elif cur_fun is not None:
                        #    self.lgr.debug('isCallToMe is call fun_hex is 0x%x fun %s cur_fun %x call_instr 0x%x' % (fun_hex, fun, cur_fun, call_instr))
                        #    pass
                        if (fun_hex is not None and fun_hex == cur_fun) or (fun is not None and self.funMatch(fun, fun_name, call_instr, False)):
                            if fun is not None:
                                new_instruct = '%s   %s' % (self.callmn, fun)
                                self.lgr.debug('fun not none %s' % fun)
                            else:
                                new_instruct = '%s   0x%x' % (self.callmn, fun_hex)
                            frame, adjust_sp = self.genFrame(call_instr, new_instruct, ptr, fun_hex, fun, lr, None, msg='isCallToMe fun_hex == cur_fun')
                            retval = (lr, adjust_sp)
                        elif cur_fun is not None and fun_hex is None and (not self.cpu.architecture == 'pp32' and (instruct[1].startswith('blr')) or (instruct[1].startswith('call') and self.decode.isReg(op1))):
                            blr_fun_name = self.fun_mgr.getBlr(call_instr) 
                            if blr_fun_name is not None:
                               if blr_fun_name != fun_name:
                                   #self.lgr.debug('stackTrace isCallToMe is a blr funs do not match, fun_name is %s, set fun_of_ip of previous frame to %s' % (fun_name, blr_fun_name))
                                   self.frames[-1].fun_of_ip = blr_fun_name 
                               #self.lgr.debug('stackTrace isCallToMe is a blr, getBlr got %s, was in fun is 0x%x (name %s)' % (blr_fun_name, cur_fun, fun_name)) 
                               cur_fun = self.fun_mgr.getFunEntry(blr_fun_name)
                               new_instruct = '%s (%s)' % (instruct[1], blr_fun_name)
                               frame, adjust_sp = self.genFrame(call_instr, new_instruct, ptr, cur_fun, blr_fun_name, lr, None, msg='isCallToMe is blr')
                               retval = (lr, adjust_sp)
                            else:
                               #self.lgr.debug('stackTrace isCallToMe is a blr, nothing from getBlr, assumig call to cur fun 0x%x (name %s)' % (cur_fun, fun_name)) 
                               frame, adjust_sp = self.genFrame(call_instr, instruct[1], ptr, fun_hex, fun_name, lr, None, msg='isCallToMe nothing from getBlr')
                               retval = (lr, adjust_sp)
                        elif fun_hex is not None and fun is not None and fun != 'None':
                            ''' LR does not suggest call to current function. Is current a different library then LR? '''
                            self.lgr.debug('try got with eip: 0x%x fun_hex 0x%x' % (eip, fun_hex))
                            if self.tryGot(lr, eip, fun_hex):
                                new_instruct = '%s   %s' % (self.callmn, fun)
                                frame, adjust_sp = self.genFrame(call_instr, new_instruct, ptr, fun_hex, fun, lr, None, msg='isCalToMe got from got')
                                #self.lgr.debug('isCallToMe got added frame %s' % frame.dumpString())
                                retval = (lr, adjust_sp)
                            else:
                                # see if fun_hex is a direct branch 
                                first_instruct = SIM_disassemble_address(self.cpu, fun_hex, 1, 0)
                                if first_instruct[1].startswith('b '):
                                    #self.lgr.debug('isCallToMe may be direct branch cur_fun 0x%x  instruct %s' % (cur_fun, first_instruct[1]))
                                    parts = first_instruct[1].split()
                                    if len(parts) == 2:
                                        dest = None
                                        try:
                                            dest = int(parts[1].strip(), 16)
                                        except:
                                            self.lgr.debug('isCallToMe failed to get dest from %s' % parts[1])
                                            pass
                                        if cur_fun is None:
                                            self.lgr.debug('isCallToMe direct branch to 0x%x cur_fun is none' % (dest))

                                        elif dest == cur_fun:
                                            new_instruct = '%s   %s' % (self.callmn, fun)
                                            frame, adjust_sp = self.genFrame(call_instr, new_instruct, ptr, fun_hex, fun, lr, None, msg='isCallToMe direct branch')
                                            retval = (lr, adjust_sp)
                                            #frame = self.FrameEntry(fun_hex, call_fname, first_instruct[1], 0, ret_addr=lr, fun_addr=cur_fun, fun_name = fun, lr_return=True)
                                            #adjust_sp = self.addFrame(frame) + self.word_size
                                            #self.lgr.debug('isCallToMe direct branch added frame %s' % frame.dumpString())
                                        else:
                                            self.lgr.debug('isCallToMe direct branch to 0x%x not to cur_fun 0x%x' % (dest, cur_fun))
                        else:
                            if cur_fun is not None and fun_hex is not None:
                                self.lgr.debug('stackTrace isCallToMe confused. fun_hex 0x%x cur_fun 0x%x instruct %s' % (fun_hex, cur_fun, instruct[1]))
                            elif fun_hex is not None:
                                self.lgr.debug('stackTrace isCallToMe confused. fun_hex 0x%x cur_fun is None instruct %s' % (fun_hex, instruct[1]))
                            else:
                                self.lgr.debug('stackTrace isCallToMe confused. fun_hex None cur_fun is None instruct %s' % (instruct[1]))
                    elif self.cpu.architecture == 'ppc32' and instruct[1] == 'bctrl':
                        retval = self.ppc32Ctrl(lr, cur_fun, fun_name, call_instr, eip, ptr)
                    else:
                        self.lgr.debug('stackTrace isCallToMe not a call %s' % (instruct[1]))
                elif cur_fun is None:
                    self.lgr.debug('isCallToMe cur_fun is None')
                else:
                    self.lgr.debug('isCallToMe cur_fun == ret_to 0x%x' % cur_fun)
        ''' Function is for ARM & PPC'''
        return retval

    def ppc32Ctrl(self, lr, cur_fun, cur_fun_name, call_instr, eip, ptr):
        retval = None, None
        ''' is a ppc32 ctrl instruction. get the reg value to see who we called '''
        #self.lgr.debug('stackTrace ppc32Ctrl lr 0x%x cur_fun 0x%x cur_fun_name %s eip 0x%x' % (lr, cur_fun, cur_fun_name, eip))
        reg_instruct = lr-8
        instruct = SIM_disassemble_address(self.cpu, reg_instruct, 1, 0)
        if not instruct[1].startswith('mtctr'):
            self.lgr.error('stackTrace ppc32Ctrl expected mtctr, got %s.' % instruct[1])
        else:
            op = instruct[1].strip().split()[1] 
            reg_value = self.decode.getValue(op, self.cpu)
            #self.lgr.debug('stackTrace ppc32Ctrl reg %s value: 0x%x' % (op, reg_value))
            called_pc = reg_value
            for i in range(4):
                called_instruct = SIM_disassemble_address(self.cpu, called_pc, 1, 0)
                if called_instruct[1].startswith('b '):
                    branch_to = int(called_instruct[1].strip().split()[1], 16)
                    new_call_addr, fun_name = self.fun_mgr.getFunNameFromInstruction(called_instruct, called_pc)
                    #self.lgr.debug('stackTrace ppc32Ctrl branch to 0x%x fun_name %s' % (new_call_addr, fun_name))
                    if self.funMatch(fun_name, cur_fun_name, called_pc, False): 
                        #self.lgr.debug('stackTrace ppc32Ctrl fun match')
                        new_instruct = 'ctrl %s' % fun_name
                        frame, adjust_sp = self.genFrame(call_instr, new_instruct, ptr, branch_to, fun_name, lr, None, msg='isCallToMe ppc ctrl')
                        retval = (lr, adjust_sp)
                        break
                called_pc = called_pc+4
            
        return retval
        

    def tryGot(self, lr, eip, fun_hex):
        retval = False
        cur_lib = self.soMap.getSOFile(eip)
        lr_lib = self.soMap.getSOFile(lr)
        #self.lgr.debug('stackTrace tryGot eip: 0x%x fun_hex 0x%x cur_lib %s lr_lib %s' % (eip, fun_hex, cur_lib, lr_lib))
        if cur_lib != lr_lib:
            ''' is 2nd instruction a load of PC? '''
            instruct = SIM_disassemble_address(self.cpu, fun_hex, 1, 0)
            second_fun_eip = fun_hex + instruct[0]
            second_instruct = SIM_disassemble_address(self.cpu, second_fun_eip, 1, 0)
            #self.lgr.debug('1st %s 2nd %s' % (instruct[1], second_instruct[1]))
            parts = second_instruct[1].split()
            if instruct[1].startswith('adrp'):
                ''' arm64 got '''
                retval = True
            elif parts[0].upper() == "LDR" and parts[2].upper() == "PC,":
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

    def funMatch(self, fun1, fun2, ip_of_call_instruct, been_above_clib):
        ''' ad hoc hacks to match 2 function signatures 
            fun1 is the function named by the call instruction.
        '''
        if fun1 is None or fun2 is None:
            self.lgr.debug('stackTrace funMatch called with fun of None')
            return False
        # TBD make data files for libc fu?
        retval = False
        self.lgr.debug('stackTrace funMatch fun1 %s fun2 %s' % (fun1, fun2))

        if '(' in fun1 and '(' in fun2:
            fun1 = fun1.split('(')[0]
            fun2 = fun2.split('(')[0]

        fun1 = fun1.replace('struct_std::','')
        fun2 = fun2.replace('struct_std::','')
        fun1 = fun1.replace('class_std::','')
        fun2 = fun2.replace('class_std::','')
        fun1 = fun1.replace('std::','')
        fun2 = fun2.replace('std::','')
        # how ugly can it get?
        fun1 = fun1.replace('>_>', '>>')
        fun2 = fun2.replace('>_>', '>>')
        #if 'basic_string' in fun1 and 'basic_string' in fun2:
        #    self.lgr.debug('does  %s' % fun1)
        #    self.lgr.debug('match %s' % fun2)

        # TBD generalize?
        fun1 = fun1.replace('snextc', 'sgetc')
        fun2 = fun2.replace('snextc', 'sgetc')

        if fun1.startswith(fun2) or fun2.startswith(fun1):
            retval = True
        else:
            if (fun1 == 'timelocal' and fun2 == 'mktime') or (fun1 == 'mktime' and fun2 == 'timelocal'):
                retval = True
        if not retval and fun2 == 'strcmp':
            if fun1 in ['wcscmp', 'mbscmp', 'mbscmp_l']:
                retval = True 
        if not retval and self.cpu.architecture in ['arm', 'arm64', 'ppc32']:
            ''' TBD seems incomplete.  Should only be meaningful for first frame? '''
            lr = self.mem_utils.getRegValue(self.cpu, 'lr')
            lr_fun_name = self.fun_mgr.funFromAddr(lr)
            #self.lgr.debug('stackTrace funMatch, try lr fun name %s' % lr_fun_name)
            if lr_fun_name is None:
                self.lgr.debug('stackTrace funMatch, lr fun name None for lr 0x%x' % lr)
            else:
                if fun1.startswith(lr_fun_name) or lr_fun_name.startswith(fun1):
                    retval = True
        if not retval:
            if fun2.startswith('IO_file_') and fun2.endswith(fun1):
                retval = True
        if not retval:
            if fun1 == 'strchr' and fun2 == 'strstr':
                # well, true for Windows mvscrt.dll anyway
                retval = True
            elif fun1 == 'atoi' and fun2 == 'strtoul':
                # true for ppc32
                retval = True
            elif fun1 == 'strcmp' and fun2 == 'strcoll':
                retval = True
            elif fun1 == 'memmove' and fun2 == 'memcpy':
                retval = True
            elif 'printf' in fun1 and fun2 == 'write':
                retval = True
        if not retval:
            fun1_entry = self.fun_mgr.getFunEntry(fun1)
            fun2_entry = self.fun_mgr.getFunEntry(fun2)
            if fun1_entry == fun2_entry:
                retval = True
        if not retval and not been_above_clib and self.soMap.isFunNotLibc(ip_of_call_instruct):
            # look for match in existing libc stack frames
            for frame in self.frames:
                #self.lgr.debug('stackTrace funMatch check clib frame %s against call %s' % (frame.fun_name, fun1))
                if frame.fun_name is not None:
                    if fun1.endswith(frame.fun_name):
                        #self.lgr.debug('stackTrace funMatch check clib frame MATCHED')
                        retval = True
                        break
        if not retval and self.cpu.architecture == 'ppc32' and self.recent_bctrl is not None:
            bctrl_fun = self.fun_mgr.getFunName(self.recent_bctrl)
            self.lgr.debug('stackTrace funMatch check bctrl 0x%x fun is %s' % (self.recent_bctrl, bctrl_fun))
            if bctrl_fun == fun2:
                self.lgr.debug('stackTrace funMatch check bctrl got match')
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
        retval = None
        if self.fun_mgr is not None:
            cur_fun = self.fun_mgr.getFun(eip)
        if cur_fun is None:
            self.lgr.debug('stackTrace doX86, curFun for eip 0x%x is NONE' % eip)
            pass
        else:
            self.lgr.debug('stackTrace doX86 cur_fun is 0x%x' % cur_fun)
            pass
        if bp == 0:
            stack_val = self.readAppPtr(esp)
            call_inst = self.followCall(stack_val)
            #self.lgr.debug('doX86 bp is zero')
            if call_inst is not None:
                #self.lgr.debug('doX86 initial sp value 0x%x is a return to address.  call_inst: 0x%x' % (stack_val, call_inst))
                instruct = SIM_disassemble_address(self.cpu, call_inst, 1, 0)
                #this_fun_name = self.funFromAddr(cur_fun)
                this_fun_name = 'unknown'
                call_addr, fun_name = self.fun_mgr.getFunNameFromInstruction(instruct, call_inst)
                if fun_name is None or fun_name == 'None':
                    fun_name = this_fun_name
                fname = self.soMap.getSOFileFull(call_inst)
                instruct_1 = self.fun_mgr.resolveCall(instruct, eip)
                was_clib = resimUtils.isClib(fname)
                prev_sp = esp
                frame, adjust_sp = self.genFrame(call_instr, instruct_1, esp, call_addr, fun_name, stack_val, esp)
                self.lgr.debug('doX86 added frame initial sp call to fun_name %s resolve call got %s fname %s frame: %S' % (fun_name, instruct_1, fname, frame.dumpString()))
            self.lgr.debug('doX86, bp is zero, tried findReturn, read bp from stack, is 0x%x' % (bp))
        else:
            ''' look for call return that is within a few bytes of SP'''
            #self.lgr.debug('doX86,  look for call return that is within a few bytes of SP')
            if cur_fun is not None:
                cur_fun_name = self.fun_mgr.funFromAddr(cur_fun)
            if cur_fun is not None and cur_fun_name is not None:
                #self.lgr.debug('doX86, cur_fun 0x%x name %s' % (cur_fun, cur_fun_name))
                pass
            fname = self.soMap.getSOFileFull(eip)
            #self.lgr.debug('doX86 back from getSOFile with fname %s' % fname)
            was_clib = resimUtils.isClib(fname)
            ret_to_addr = bp + self.mem_utils.wordSize(self.cpu)
            ret_to = self.readAppPtr(ret_to_addr)
            #if True:
            if ret_to is not None and not (self.soMap.isMainText(eip) and self.soMap.isMainText(ret_to)):
                ''' TBD trying to be smarter to avoid bogus frames.  Cannot only rely on not being main because such things are called in static-linked programs. '''
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
            if ret_to is None or not self.soMap.isCode(ret_to, self.tid):
                self.frames[0].ret_addr = None
            else:
                self.frames[0].ret_addr = ret_to
            self.frames[0].ret_to_addr = ret_to_addr
            self.frames[0].fun_addr = cur_fun
            self.frames[0].fun_name = cur_fun_name
            if cur_fun is not None and ret_to is not None:
                self.lgr.debug('doX86, set frame 0 ret_to_addr 0x%x  ret_addr 0x%x  fun_addr 0x%x' % (ret_to_addr, ret_to, cur_fun))
            else:
                self.lgr.debug('doX86, set frame 0 ret_to or cur_fun is None')
        
        self.lgr.debug('doX86 enter loop. bp is 0x%x' % bp)
        ''' attempt to weed out bogus stack frames '''
        been_to_main = False
        if len(self.frames) > 1:
            prev_sp = self.frames[-1].sp + self.mem_utils.wordSize(self.cpu)
        while True:
            if bp == 0 and len(self.frames)>1:
                self.lgr.debug('stackTrace doX86, bp is zero frames len %d, bail' % len(self.frames))
                bp = prev_sp
                break
            pushed_bp = self.readAppPtr(bp)
            if pushed_bp == bp:
                self.lgr.debug('stackTrace doX86, pushed bp same as bp, bail')
                bp = prev_sp
                break
            ret_to_addr = bp + self.mem_utils.wordSize(self.cpu)
            ret_to = self.readAppPtr(ret_to_addr)
            if ret_to is None:
                self.lgr.debug('stackTrace doX86 ret_to None, bail')
                bp = prev_sp
                break
            if not self.soMap.isCode(ret_to, self.tid):
                self.lgr.debug('stackTrace doX86 ret_to 0x%x is not code, bail' % ret_to)
                bp = prev_sp
                break

            ret_to_fname = self.soMap.getSOFileFull(ret_to)
            self.lgr.debug('stackTrace dox86 ret_to 0x%x ret_to_fname %s' % (ret_to, ret_to_fname))
            if was_clib and not resimUtils.isClib(ret_to_fname):
                self.lgr.debug('stackTrace dox86 Was clib, now not, look for other returns? prev_sp is 0x%x bp is 0x%x, pushed_bp is 0x%x' % (prev_sp, bp, pushed_bp))
                max_bytes = bp - prev_sp
                other_ret_to = self.findReturnFromCall(prev_sp, cur_fun, max_bytes=max_bytes, eip=call_inst)
                if other_ret_to is not None:
                    self.lgr.debug('stackTrace dox86 found xtra stack frame')
                else:
                    self.lgr.debug('stackTrace dox86 found NO xtra stack frame')

            ws = self.mem_utils.wordSize(self.cpu)
            self.lgr.debug('stackTrace doX86 pushed_bp was 0x%x ret_to is 0x%x, ret_to_addr was 0x%x bp was 0x%x ws %d was_clib? %r' % (pushed_bp, ret_to, ret_to_addr, bp, ws, was_clib))
            call_inst = self.followCall(ret_to)
            if call_inst is not None:
                added_frame = False
                self.lgr.debug('stackTrace doX86 ret_to 0x%x followed call, call inst addr 0x%x' % (ret_to, call_inst))
                instruct = SIM_disassemble_address(self.cpu, call_inst, 1, 0)
                call_addr, fun_name = self.fun_mgr.getFunNameFromInstruction(instruct, call_inst)
                instruct_1 = self.fun_mgr.resolveCall(instruct, call_inst)
                fname = self.soMap.getSOFileFull(call_inst)
        
                #if call_addr is not None and been_to_main and not self.soMap.isMainText(call_addr):
                if call_addr is not None and been_to_main and not self.soMap.isFunNotLibc(call_addr):
                    #self.lgr.debug('stackTrace doX86 been to main but now see lib? 0x%x bail' % call_addr)
                    ''' TBD hacky return value'''
                    bp = 0
                    break
                if call_addr is not None:
                     
                    if cur_fun is not None:
                        self.lgr.debug('stackTrace x86 call addr 0x%x fun %s cur_fun: 0x%x' % (call_addr, fun_name, cur_fun))
                    else:
                        self.lgr.debug('stackTrace x86 call addr 0x%x fun %s cur_fun is None' % (call_addr, fun_name))
                    self.lgr.debug('stackTrace 8x86 pushed bp is 0x%x' % pushed_bp)
                    ''' TBD fix for windows '''
                    if not self.top.isWindows() and call_addr != cur_fun and quick_return is None:
                        '''
                        self.lgr.debug('stackTrace doX86 call findReturnFromCall esp 0x%x' % esp)
                        ret_addr = self.findReturnFromCall(esp, cur_fun)
                        #if ret_addr is not None and self.soMap.isMainText(ret_addr):
                        if ret_addr is not None and self.soMap.isFunNotLibc(ret_addr):
                             been_to_main = True
                        self.lgr.debug('stackTrace doX86 back from findReturnFromCall')
                        if ret_addr is not None:
                            added_frame = True
                        '''
                        was_clib = resimUtils.isClib(fname)
                        prev_sp = ret_to_addr - self.mem_utils.wordSize(self.cpu)
                        frame, adjust_sp = self.genFrame(call_inst, instruct_1, prev_sp, call_addr, fun_name, ret_to, ret_to_addr)
                        self.lgr.debug('stackTrace x86 added frame add call_inst 0x%x  inst: %s fname %s frame: %s' % (call_inst, instruct_1, fname, frame.dumpString())) 
                        added_frame = True

                    else:
                        #if self.soMap.isMainText(call_addr):
                        if self.soMap.isFunNotLibc(call_addr):
                             been_to_main = True
                    
                else:
                    was_clib = resimUtils.isClib(fname)
                    prev_sp = ret_to_addr - self.mem_utils.wordSize(self.cpu)
                    frame, adjust_sp = self.genFrame(call_inst, instruct_1, prev_sp, call_addr, fun_name, ret_to, ret_to_addr)
                    self.lgr.debug('stackTrace x86 no call_addr added frame add call_inst 0x%x  inst: %s fname %s frame: %s' % (call_inst, instruct_1, fname, frame.dumpString())) 
                    #self.lgr.debug(frame.dumpString())
                    pass
                if self.fun_mgr is not None: 
                    cur_fun = self.fun_mgr.getFun(ret_to)
                bp = pushed_bp
                ''' only add if not added above'''
                if call_addr is not None and not added_frame:
                    was_clib = resimUtils.isClib(fname)
                    prev_sp = ret_to_addr - self.mem_utils.wordSize(self.cpu)
                    frame, adjust_sp = self.genFrame(call_inst, instruct_1, prev_sp, call_addr, fun_name, ret_to, ret_to_addr)
                    self.lgr.debug('stackTrace x86 added frame add call_inst 0x%x  inst: %s fname: %s frame: %s' % (call_inst, instruct_1, fname, frame.dumpString())) 
                    #self.lgr.debug(frame.dumpString())
            else:
                #self.lgr.debug('stackTrace x86, no call_inst from ret_to 0x%x' % ret_to)
                break
        return bp
   
    def findReturnFromCall(self, ptr, cur_fun, max_bytes=900, eip=None):        
        ''' See if an x86 return instruction is within a max_bytes of the SP.  Handles clib cases where ebp is not pushed. 
            Likely more complicated then it needs to be.  Many special cases.
            Will add at most one frame.
        '''
        got_fun_name = None
        cur_fun_name = None
        cur_is_clib = False
        if cur_fun is not None:
            cur_fun_name = self.fun_mgr.funFromAddr(cur_fun)
            self.lgr.debug('stackTrace findReturnFromCall START ptr 0x%x cur_fun 0x%x (%s)' % (ptr, cur_fun, cur_fun_name))
            pass
        else:
            self.lgr.debug('stackTrace findReturnFromCall START ptr 0x%x cur_fun NONE' % (ptr))
            pass
        esp = self.reg_frame['sp']
        current_instruct = None
        if eip is not None:
            current_instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)[1]
            #lib_file = self.top.getSO(eip)
            lib_file = self.soMap.getSOFileFull(eip)
            if resimUtils.isClib(lib_file):
                cur_is_clib = True
            #self.lgr.debug('stackTrace findReturnFromCall given eip 0x%x, is clib? %r for %s' % (eip, cur_is_clib, current_instruct))
        retval = None
        limit = ptr + max_bytes
        call_ip = None
        #while retval is None and ptr < limit:
        while ptr < limit:
            if retval is not None and call_ip is not None:
                if self.soMap.isFunNotLibc(call_ip):
                    self.lgr.debug('stackTrace findReturnFromCall, call_ip is in main, we are done')
                    break
            val = self.readAppPtr(ptr)
            if val is None:
                #self.lgr.debug('stackTrace findReturnFromCall, failed to read from 0x%x' % ptr)
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
            self.lgr.debug('stackTrace findReturnFromCall ptr 0x%x val 0x%x  limit 0x%x' % (ptr, val, limit))    
            if self.soMap.isCode(val, self.tid):
                self.lgr.debug('stackTrace findReturnFromCall is code val 0x%x ptr was 0x%x' % (val, ptr))
                call_ip = self.followCall(val)
                if call_ip is not None:
                    fname = self.soMap.getSOFileFull(call_ip)
                    if cur_fun is None and self.fun_mgr is not None:
                        cur_fun = self.fun_mgr.getFun(call_ip)
                        if cur_fun is not None:
                            self.lgr.debug('stackTrace findReturnFromCall had no cur_fun, set to 0x%x' % cur_fun)
                            pass
                        else:
                            self.lgr.debug('stackTrace findReturnFromCall, still no curfun call_ip was 0x%x' % call_ip)
                            pass
                    instruct_of_call = SIM_disassemble_address(self.cpu, call_ip, 1, 0)
                    instruct = instruct_of_call[1]
                    self.lgr.debug('stackTrace findReturnFromCall call_ip 0x%x  %s' % (call_ip, instruct))
                    call_addr, fun_name = self.fun_mgr.getFunNameFromInstruction(instruct_of_call, call_ip)
                    if call_addr is not None:
                        if cur_fun is not None:
                            self.lgr.debug('stackTrace findReturnFromCall call_addr 0x%x cur_fun 0x%x fun_name %s cur_fun_name %s' % (call_addr, cur_fun, fun_name, cur_fun_name))
                        else:
                            self.lgr.debug('stackTrace findReturnFromCall call_addr 0x%x cur_fun none fun_name %s cur_fun_name %s' % (call_addr, fun_name, cur_fun_name))
                    if call_addr == cur_fun or (fun_name == cur_fun_name) or self.sameFun(fun_name, cur_fun_name):
                        if fun_name is not None:
                            instruct = '%s %s' % (self.callmn, fun_name)
                        ret_addr = call_ip + instruct_of_call[0] 
                        frame, adjust_sp = self.genFrame(call_ip, instruct, ptr, None, fun_name, ret_addr, ptr)
                        retval = self.readAppPtr(ptr)
                        self.lgr.debug('stackTrace findReturnFromCall xx Found x86 call to %s instruct:%s  ret_to_addr 0x%x ret 0x%x added frame' % (cur_fun, instruct, ptr, retval))
                        break
                    elif call_addr is None:
                        # assume call to previous function
                        prev_fun = self.frames[-1].fun_of_ip
                        ret_addr = call_ip + instruct_of_call[0] 
                        frame, adjust_sp = self.genFrame(call_ip, instruct, ptr, None, prev_fun, ret_addr, ptr)
                        retval = self.readAppPtr(ptr)
                        self.lgr.debug('stackTrace findReturnFromCall no call_addr found x86 call instruct:%s  ret_to_addr 0x%x ret 0x%x added frame assuming call to function gotten from previous frame %s' % (instruct, ptr, retval, prev_fun))
                        break
                    elif self.fun_mgr.isRelocate(call_addr):
                        self.lgr.debug('stackTrace findReturnFromCall 0x%x is relocate')
                        #new_call_addr, fun_name = self.fun_mgr.getFunNameFromInstruction(instruct, call_addr)
                        instruct = '%s %s' % (self.callmn, fun_name)
                        ret_addr = call_ip + instruct_of_call[0] 
                        frame, adjust_sp = self.genFrame(call_ip, instruct, ptr, call_addr, fun_name, ret_addr, ptr)
                        self.lgr.debug('stackTrace findReturnFromCall relocated frame is %s' % frame.dumpString())
                        retval = self.readAppPtr(ptr)
                        break
                    elif (fun_name is not None and fun_name.startswith('memcpy')) and (current_instruct is not None and current_instruct.startswith('rep movsd')):
                        # hacks are us
                        ret_addr = call_ip + instruct_of_call[0] 
                        frame, adjust_sp = self.genFrame(call_ip, instruct, ptr, call_addr, fun_name, ret_addr, ptr)
                        retval = self.readAppPtr(ptr)
                        self.lgr.debug('stackTrace findRetrunFromCall memcpy/rep x86 mov hack call %s ret_t_addr: 0x%x ret: 0x%x' % (instruct, ptr, retval))
                        break
                    else:
                        ''' look for GOTish jump to dword '''
                        retval = self.isGOT(ptr, call_addr, cur_fun, cur_fun_name, instruct_of_call, call_ip, fname, cur_is_clib)
                        if retval is not None:
                            self.lgr.debug('stackTrace findReturnFromCall from isGot got 0x%x' % retval)
                            break
                #else:
                #    self.lgr.debug('call_ip is None')
            ptr = ptr + self.mem_utils.wordSize(self.cpu)
        #if ptr >= limit:
        #    self.lgr.debug('stackTrace findReturnFromCall hit stack limit of 0x%x' % limit)
        return retval                

    def isGOT(self, ptr, call_addr, cur_fun, cur_fun_name, instruct_of_call, call_ip, fname, cur_is_clib, skip_clib=False):
        # ptr -- current sp
        # call_addr -- destination of call
        # cur_fun -- address of current function
        # instruct_of_call -- call instruction
        # call_ip  -- address of call call instruction
        retval = None
        first_instruct = SIM_disassemble_address(self.cpu, call_addr, 1, 0)
        call_to_actual, actual_fun = self.checkRelocate(call_addr)
        #self.lgr.debug('stackTrace isGOT call_addr 0x%x first_instruct is %s cur_fun_name %s fname %s instruct_of_call %s call_ip 0x%x cur_is_clib %r' % (call_addr, first_instruct[1], cur_fun_name, fname, instruct_of_call, call_ip, cur_is_clib))
        skip_this = False
        if call_to_actual is not None:
            prev_fnamex = self.frames[-1].fname
            actual_fname = self.soMap.getSOFile(call_to_actual)
            #self.lgr.debug('stackTrace isGOT call_to_actual 0x%x actual_fname %s prev_fnamex %s' % (call_to_actual, actual_fname, prev_fnamex))
            if actual_fname not in [fname, prev_fnamex]:
                skip_this = True
            if call_to_actual in self.black_list:
                #self.lgr.debug('stackTrace isGOT call_to_actual 0x%x in blacklist, skip this' % (call_to_actual))
                skip_this = True
        if skip_this:
            #self.lgr.debug('stackTrace isGOT actual call is not to SO we were just in, bail') 
            pass
        elif first_instruct[1].lower().startswith('jmp dword') or first_instruct[1].lower().startswith('jmp qword'): 
            fun_name = None
            new_call_addr, fun_name = self.fun_mgr.getFunNameFromInstruction(first_instruct, call_addr)
            if new_call_addr is not None:
                instruct = '%s %s' % (self.callmn, fun_name)
                orig_call_addr = call_addr
                call_addr = new_call_addr
                #self.lgr.debug('stackTrace isGOT is jmp, call_addr now 0x%x' % call_addr)
                got_fun_name = self.fun_mgr.funFromAddr(call_addr)
                if got_fun_name is None:
                    got_entry = self.readAppPtr(call_addr)
                    got_fun_name = self.fun_mgr.funFromAddr(got_entry)
                    #self.lgr.debug('stackTrace isGOT fun name from call_addr 0x%x was none.  Tried reading that pointer and got 0x%x, yielding fun name of %s' % (call_addr, got_entry, got_fun_name))
                else:
                    #self.lgr.debug('stackTrace isGOT got fun %s' % got_fun_name)
                    pass
                instruct = self.fun_mgr.resolveCall(instruct_of_call, call_addr)
                if call_addr == cur_fun:
                    ret_addr = call_ip + instruct_of_call[0] 
                    frame, adjust_sp = self.genFrame(call_ip, instruct, ptr, call_addr, fun_name, ret_addr, ptr)
                    retval = self.readAppPtr(ptr)
                    #self.lgr.debug('stackTrace isGOT Found x86 call %s  ret_to_addr 0x%x ret 0x%x added frame' % (instruct, ptr, retval))
                elif cur_fun_name is None and cur_is_clib:
                    got_fun_name = self.fun_mgr.funFromAddr(orig_call_addr)
                    self.lgr.warning('stackTrace isGOT no cur_fun_name and currently in clib.  Maybe clib was not analyzed? using original got addr 0x%x' % orig_call_addr)
                    ret_addr = call_ip + instruct_of_call[0] 
                    frame, adjust_sp = self.genFrame(call_ip, instruct, ptr, orig_call_addr, got_fun_name, ret_addr, ptr)
                elif cur_fun_name is not None and got_fun_name is not None and got_fun_name.startswith(cur_fun_name):
                    ret_addr = call_ip + instruct_of_call[0] 
                    frame, adjust_sp = self.genFrame(call_ip, instruct, ptr, call_addr, cur_fun_name, ret_addr, ptr)
                    retval = self.readAppPtr(ptr)
                    #self.lgr.debug('stackTrace isGOT Found GOT x86 call %s  is got %s   add entry  call_ip 0x%x  call_addr: 0x%x ret_to_addr: 0x%x ret: 0x%x added frame' % (instruct, got_fun_name, call_ip, call_addr, ptr, retval))
                elif got_fun_name is not None and cur_is_clib:
                    ret_addr = call_ip + instruct_of_call[0] 
                    frame, adjust_sp = self.genFrame(call_ip, instruct, ptr, call_addr, got_fun_name, ret_addr, ptr)
                    retval = self.readAppPtr(ptr)
                    #self.lgr.debug('stackTrace isGOT Found x86 GOT, though no current fuction found. call %s  is got %s   added frame  call_ip 0x%x  call_addr: 0x%x ret_to_addr: 0x%x ret: 0x%x' % (instruct, got_fun_name, call_ip, call_addr, ptr, retval))
                elif got_fun_name is not None and not skip_clib:
                    ret_addr = call_ip + instruct_of_call[0] 
                    frame, adjust_sp = self.genFrame(call_ip, instruct, ptr, call_addr, got_fun_name, ret_addr, ptr)
                    retval = self.readAppPtr(ptr)
                    #self.lgr.debug('stackTrace isGOT Found x86 GOT, though current fuction is not called function. call %s  is got %s added frame call_ip 0x%x  call_addr: 0x%x ret_to_addr: 0x%x ret: 0x%x' % (instruct, got_fun_name, call_ip, call_addr, ptr, retval))
            else:
                prev_fun = self.frames[-1].fun_of_ip
                if prev_fun is None:
                    prev_fun = self.fun_mgr.funFromAddr(call_addr)
                #self.lgr.debug('stackTrace isGOT call_addr is none from %s, assume GOT call to function %s' % (first_instruct[1], prev_fun))
                instruct_str = '%s   %s' % (self.callmn, prev_fun)
                ret_addr = call_ip + instruct_of_call[0] 
                frame, adjust_sp = self.genFrame(call_ip, instruct_str, ptr, None, prev_fun, ret_addr, ptr)
                retval = self.readAppPtr(ptr)
                #self.lgr.debug('stackTrace isGOT assuming it is a jump to %s ret_to_addr 0x%x ret 0x%x added frame' % (prev_fun, ptr, retval))
        return retval

    def sameFun(self, fun1, fun2):
        retval = False
        pile1 = ['strcmp', 'wcscmp', 'mbscmp', 'mbscmp_l']
        if fun1 in pile1 and fun2 in pile1:
            retval = True
        return retval
 
    def getCallTo(self, call_ip): 
        fun_name = None
        call_to = None
        instruct = SIM_disassemble_address(self.cpu, call_ip, 1, 0)[1]
        op2, op1 = self.decode.getOperands(instruct)
        #self.lgr.debug('stackTrace getCallTo call_ip 0x%x instruct %s op1 %s' % (call_ip, instruct, op1))
        if (not self.cpu.architecture == 'ppc32' and instruct.startswith('blr')) or (instruct.startswith('call') and self.decode.isReg(op1)):
            #self.lgr.debug('stackTrace getCallTo is blr call_ip 0x%x %s' % (call_ip, instruct))
            fun_name = self.fun_mgr.getBlr(call_ip) 
            #self.lgr.debug('stackTrace getCallTo fun name from getblr is %s' % fun_name)
            if fun_name is not None:
                call_to = self.fun_mgr.getFunEntry(fun_name)
                if call_to is None:
                    self.lgr.debug('stackTrace getCallTo fun name %s got zip' % (fun_name))
        elif instruct == 'bctrl':
            call_to = self.mem_utils.getRegValue(self.cpu, 'ctr')
            fun_name = self.fun_mgr.getFunName(call_to)
            self.lgr.debug('stackTrace getCallTo bctrl count reg 0x%x fun name %s' % (call_to, fun_name))
        else:
            call_to_s = instruct.split()[1]
            #self.lgr.debug('stackTrace getCallTo check call to %s' % call_to_s)
            try:
                call_to = int(call_to_s, 16)
            except:
                pass 
            if call_to is not None:
                fun_name = self.fun_mgr.getFunName(call_to)
        return call_to, fun_name

    def doTrace(self):
        if self.tid == 0 or self.tid == 1:
            #self.lgr.debug('stackTrack doTrace called with tid 0')
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

        instruct_tuple = SIM_disassemble_address(self.cpu, eip, 1, 0)
        instruct = instruct_tuple[1]
        '''
        if self.mem_utils.isKernel(eip):
            self.lgr.debug('stackTrace eip in kernel, instruct %s .' % instruct)
            if instruct == 'sysret64':
                eip = self.mem_utils.getRegValue(self.cpu, 'rcx')
            elif instruct == 'sysret':
                eip = self.mem_utils.getRegValue(self.cpu, 'ecx')
            else:
                self.lgr.warning('stackTrace eip kernel, instruct %s not handled.' % instruct)
            instruct_tuple = SIM_disassemble_address(self.cpu, eip, 1, 0)
            instruct = instruct_tuple[1]
            self.lgr.debug('stackTrace eip in kernel new eip 0x%x instruct %s .' % (eip, instruct))
        '''

        if self.stack_base is not None:
            self.lgr.debug('stackTrace doTrace tid:%s esp is 0x%x eip 0x%x  stack_base 0x%x' % (self.tid, esp, eip, self.stack_base))
            pass
        else:
            self.lgr.debug('stackTrace doTrace NO STACK BASE tid:%s esp is 0x%x eip 0x%x' % (self.tid, esp, eip))
            pass
        done  = False
        count = 0
        #ptr = ebp
        ptr = esp
        been_in_main = False
        been_above_clib = False
        prev_ip = None
        if self.soMap.isMainText(eip):
            been_in_main = True
        if self.soMap.isFunNotLibc(eip):
            been_above_clib = True
            if self.cpu.architecture not in ['arm', 'arm64', 'ppc32']:
                self.lgr.debug('stackTrace starting in function that is not libc.  set prev_ip to eip: 0x%x' %eip)
                prev_ip = eip
            else:
                lr = self.reg_frame['lr']
                #self.lgr.debug('stackTrace arm lr is 0x%x should we set prev_ip, i.e., should we see if we should check isCallToMe?' % lr)
                #if self.soMap.isMainText(self.reg_frame['lr']):
                #    self.lgr.debug('stackTrace arm lr 0x%x is in Main' % lr)
                #else:
                #    self.lgr.debug('stackTrace arm lr 0x%x is NOT in Main' % lr)
        #prev_ip = eip
        if self.fun_mgr is None:
            self.lgr.warning('stackTrace has no ida functions')
            return

        ''' record info about current IP '''
       
        fname = self.soMap.getSOFileFull(eip)
        prev_fname = fname
        instruct = self.fun_mgr.resolveCall(instruct_tuple, eip)
        first_fun_addr = self.fun_mgr.getFun(eip)
        first_fun_name = self.fun_mgr.getFunName(first_fun_addr)
        frame, adjust_sp = self.genFrame(eip, instruct, ptr, None, None, None, None, msg='first frame')
        if self.cpu.architecture.startswith('x86') and adjust_sp > 0:
            self.lgr.debug('stackTrace adjust for first frame 0x%x' % adjust_sp)
            ptr = ptr + adjust_sp
        if first_fun_addr is not None:
            #self.lgr.debug('stackTrace doTrace begin tid:%s cur eip 0x%x sp: 0x%x instruct %s  fname %s skip_recurse: %r first_fun_addr 0x%x fun name %s' % (self.tid, eip, esp, instruct, fname, self.skip_recurse, first_fun_addr, first_fun_name))
            pass
        else:
            if self.fun_mgr.haveFuns(fname) and self.top.isWindows():
                ''' obscure avoidance of ghost retval at top of stack '''
                self.lgr.debug('stackTrace doTrace no fun name though we have funs for %s, obscure avoidance of ghost retval at top of stack' % fname)
                ptr = ptr + self.word_size
            #self.lgr.debug('stackTrace doTrace begin tid:%s cur eip 0x%x sp: 0x%x instruct %s  fname %s skip_recurse: %r first_fun_addr is none' % (self.tid, eip, esp, instruct, fname, self.skip_recurse))
        ''' TBD *********** DOES this prev_ip assignment break frames that start in libs? '''
        if prev_ip is None and self.cpu.architecture in ['arm', 'arm64', 'ppc32']:
            prev_ip, adjust_sp = self.isCallToMe(fname, eip, ptr)
            if prev_ip is not None:
                # TBD need explaination of why we put the word back here that was subtracted in addFrame.
                ptr = ptr + adjust_sp + self.word_size
                self.lgr.debug('doTrace back from isCallToMe prev_ip set to 0x%x ptr adjusted by 0x%x now 0x%x' % (prev_ip, adjust_sp, ptr))
            else:
                self.lgr.debug('doTrace back from isCallToMe prev_ip None, must not be call to me')
                pass
        
        only_module = False
        cur_fun = None
        cur_fun_name = None
        if self.fun_mgr is not None:

            if self.top.isVxDKM():
                if self.soMap.inVxWorks(eip):
                    module = self.recordVxCall(eip) 
                    if module is not None and module != 'vxWorks':
                        self.lgr.debug('doTrace in module %s, set only_module to ignore vxworks' % module)
                        only_module = True
                    else:
                        self.lgr.debug('doTrace in module %s, keep looking at frames in vxworks' % module)
                else:
                    # ignore stack frames that are in vxworks
                    only_module = True 
                    self.lgr.debug('doTrace not in vxWorks, set only_module')
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
                prev_ip = eip
                self.lgr.debug('doTrace starting eip: 0x%x is in fun %s 0x%x forcing prev_ip to eip' % (eip, cur_fun_name, cur_fun))

        ''' See if BP register should be used to find frames and/or adjust sp '''
        hacked_bp = False
        if self.cpu.architecture.startswith('x86'):
            # TBD need way to indicate whether bp register is used
            if not self.top.isWindows():
                if self.word_size != 8 and self.use_bp:
                    self.lgr.debug('doTrace call doX86')
                    bp = self.doX86()
                    if bp == 0 and len(self.frames)>1:
                        ''' walked full stack '''
                        self.lgr.debug('stackTrace doTrace starting doX86 got it, we are done')
                        done = True
                    else:
                        self.lgr.debug('stackTrace doTrace after doX86 bp 0x%x num frames %s' % (bp, len(self.frames)))
                        if len(self.frames) > 5:
                            ''' TBD revisit this wag '''
                            done = True
                        elif self.soMap.isMainText(self.frames[-1].ip):
                            done = True
                        elif bp is not None:
                            ptr = bp
                else:
                    # TBD at least add some guard rails
                    new_ptr = self.hackBP(ptr, fname)
                    #self.lgr.debug('stackTrace doTrace new_ptr from hackBP is 0x%x' % new_ptr)
                    if new_ptr is not None and new_ptr != 0:
                        ptr = new_ptr
                        cur_fun_name = None
                        hacked_bp = True
                        self.prev_frame_sp = ptr
            else:
                #self.lgr.debug('stackTrace doTrace Windows check bp, fname is %s' % fname)
                new_ptr = self.windowsBP(ptr, fname)
                if new_ptr is not None:
                    ptr = new_ptr
                    cur_fun_name = None
                    hacked_bp = True
        start_ptr = ptr
        start_cur_fun_name = cur_fun_name
        start_cur_fun = cur_fun
        start_prev_ip = prev_ip
        start_hacked_bp = hacked_bp
        start_been_above_clib = been_above_clib
        start_been_in_main = been_in_main
        fail_count = 0 
        while not done and (count < 9000): 
            ''' ptr iterates through stack addresses.  val is the value at that address '''
            #if not been_above_clib and (ptr - self.prev_frame_sp) > 1500:
           
            # TBD ignoring when only one frame 
            #self.lgr.debug('stackTrace loop count %d' % count)
            #if len(self.frames) > 1 and self.cpu.architecture not in ['arm', 'arm64'] and (self.mindTheGap(ptr) or self.mind_the_gap):
            if len(self.frames) > 0 and self.cpu.architecture.startswith('x86') and (self.mindTheGap(ptr) or self.mind_the_gap):
            #if self.cpu.architecture not in ['arm', 'arm64'] and (self.mindTheGap(ptr) or self.mind_the_gap):
                self.lgr.debug('stackTrace mind the fgap')
                self.mind_the_gap = False
                fun_addr = self.frames[-1].fun_addr
                if fun_addr is None:
                    self.lgr.debug('stackTrace large gap but no function address num frames %d' % len(self.frames))
                    #SIM_break_simulation('remove this')
                    self.lgr.debug('offending frame: %s' % self.frames[-1].dumpString())
                    return

                prev_frame_fun = self.fun_mgr.getFun(self.frames[-1].fun_addr)
                if prev_frame_fun is None:
                    self.lgr.debug('stackTrace large gap but no previous frame function frames %d' % len(self.frames))
                    #SIM_break_simulation('remove this')
                    self.lgr.debug('offending frame: %s' % self.frames[-1].dumpString())
                    return
                prev_frame_fun_name = self.frames[-1].fun_of_ip
                self.lgr.debug('stackTrace MIND THE GAP ptr now 0x%x, last frame sp was 0x%x will add  to blacklist: prev_fun 0x%x fun_name %s number of frames %d' % (ptr, self.prev_frame_sp, prev_frame_fun, prev_frame_fun_name, len(self.frames)))
                if len(self.frames) > 1:
                    frames_found = True
                else:
                    frames_found = False
                    #self.lgr.debug('stackTrace gap with no frames found, will increment gap_reset_to at the end')
                hacked_bp = start_hacked_bp
                count = 0
                # RESET frames
                if self.gap_reset_to <= self.most_frames:
                    self.frames = list(self.best_frames[:self.gap_reset_to])
                    self.lgr.debug('stackTrace gap  gap_reset_to is %d len of frames now %d best frames len was %d' % (self.gap_reset_to, len(self.frames), len(self.best_frames))) 
                else:
                    self.lgr.error('stackTrace gap reset gap_reset_to %d is greater than any most frames %d' % (self.gap_reset_to, self.most_frames))
                    #SIM_break_simulation('remove this')
                    break
                if self.gap_reset_to > 1 and len(self.frames)>0:
                    ptr = self.frames[-1].sp
                    prev_ip = self.frames[-1].ip
                    cur_fun_name = self.frames[-1].fun_of_ip
                else:
                    ptr = start_ptr
                    cur_fun_name = start_cur_fun_name
                    prev_ip = start_prev_ip
                # TBD fix this if reset get incremented
                been_above_clib = start_been_above_clib
                been_in_main = start_been_in_main
                if not frames_found and len(self.frames)>0:
                    if fail_count > 0:
                        self.lgr.error('stackTrace gap, already failed.  TBD adjust stack?')
                        #SIM_break_simulation('remove this')
                        return
                    fail_count = fail_count + 1
                    #self.gap_reset_to = self.gap_reset_to + 1
                    self.black_list = []
                    self.most_frames = 0
                    self.best_frames = []
                    ptr = self.frames[-1].sp
                    start_ptr = ptr
                    self.lgr.debug('stackTrace gap no frames found, try ignoring bp')
                    #self.lgr.debug('stackTrace gap_reset_to now %d' % self.gap_reset_to)
                else: 
                    if prev_frame_fun in self.black_list:
                        self.lgr.error('stackTrace fun 0x%x already in blacklist' % prev_frame_fun)
                        #SIM_break_simulation('remove this')
                        break
                    self.black_list.append(prev_frame_fun)
                self.lgr.debug('stackTrace gap minding done.  ptr 0x%x been_above_clib %r cur_fun_name %s' % (ptr, been_above_clib, cur_fun_name))
                continue
            # ABOVE is mindTheGap, TBD move to function.
            if len(self.frames) > 0:
                cur_fun = self.frames[-1].fun_addr_of_ip 
                cur_fun_name = self.frames[-1].fun_of_ip 
                prev_ip = self.frames[-1].ip
                #self.lgr.debug('stackTrace after mindTheGap prev_ip 0x%x' % prev_ip)
            else:
                self.lgr.error('stackTrace after mindTheGap no stack frames?')
                SIM_break_simulation('remove this')
                return
            
            val = self.readAppPtr(ptr)
            if val is None:
                self.lgr.debug('stackTrace, failed to read from 0x%x' % ptr)
                count += 1
                ptr = ptr + self.mem_utils.wordSize(self.cpu)
                done = True
                continue
            if only_module and self.soMap.inVxWorks(val):
                count += 1
                ptr = ptr + self.mem_utils.wordSize(self.cpu)
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
            if hacked_bp and len(self.frames)>1:
                hacked_bp = False
            if self.soMap.isCode(val, self.tid):
                ip_of_call_instruct = self.followCall(val)
                if ip_of_call_instruct is not None:
                   self.lgr.debug('stackTrace is code: 0x%x from ptr 0x%x   PC of call is 0x%x' % (val, ptr, ip_of_call_instruct))
                   pass
                else:
                   self.lgr.debug('stackTrace is code not follow call: 0x%x from ptr 0x%x   ' % (val, ptr))
                   pass
                   
                if been_in_main and not self.soMap.isMainText(val):
                    ''' once been_in_main assume we never leave? what about callbacks?'''
                    #self.lgr.debug('stackTrace been_in_main is true')
                    skip_this = True
                
                if not skip_this and ip_of_call_instruct is not None:    
                    call_to, called_fun_name = self.getCallTo(ip_of_call_instruct)
                    if call_to is not None:
                        if called_fun_name is not None:
                            fun_name = called_fun_name
                        self.lgr.debug('stackTrace call_to 0x%x called_fun_name %s' % (call_to, called_fun_name))
                             
                    #else:
                    #    self.lgr.debug('stackTrace call_to None')
                if not skip_this and been_above_clib and self.fun_mgr is not None and ip_of_call_instruct is not None and prev_ip is not None:
                    # Note "been_above_clib" simply means we've been in a non-clib library.
                    if call_to is not None:
                        #self.lgr.debug('stackTrace been above libc call_to 0x%x ' % call_to)
                        fname, start, end = self.soMap.getSOInfo(call_to)
                        if not self.fun_mgr.soChecked(call_to):
                            ''' should we add ida function analysys? '''
                            # windows can take forever to search.  so, no.
                            if not self.top.isWindows() and not self.top.isVxDKM() and (self.fun_mgr.getFunName(call_to) is None):
                                self.lgr.debug('stackTrace so check of %s the call_to of 0x%x not in IDA funs?' % (fname, call_to))
                                if fname is not None:
                                    full_path = self.top.getAnalysisPath(fname)
                                    if full_path is not None:
                                        #self.lgr.debug('stackTrace call add for %s' % full_path)
                                        self.fun_mgr.add(full_path, start)
                                    else:
                                        self.lgr.debug('stackTrace, adding analysis? failed to get full_path from fname %s' % fname)
                            self.fun_mgr.soCheckAdd(call_to) 
                        
                        if not self.fun_mgr.isFun(call_to):
                            altered_call_to = self.fun_mgr.getFun(call_to)
                            if altered_call_to is not None:
                                #self.lgr.debug('stackTrace call_to 0x%x was not an entry, adjusted to function entry 0x%x' % (call_to, altered_call_to))
                                call_to = altered_call_to
                         
                        if self.fun_mgr.isFun(call_to):
                            self.lgr.debug('stackTrace call_to 0x%x is fun prev_ip is 0x%x' % (call_to, prev_ip))
                            if not self.fun_mgr.inFun(prev_ip, call_to, call_ip=ip_of_call_instruct):
                                first_instruct = SIM_disassemble_address(self.cpu, call_to, 1, 0)
                                #self.lgr.debug('stackTrace not inFun.  first_instruct is %s' % first_instruct[1])
                                if self.cpu.architecture in ['arm', 'arm64', 'ppc32'] and first_instruct[1].lower().startswith('b '):
                                    skip_this = self.checkArmDirect(first_instruct, call_to, prev_ip, ptr, fname, ip_of_call_instruct)
                                elif self.top.isVxDKM(cpu=self.cpu):
                                    #self.lgr.debug('stackTrace call checkVxDirect for fun 0x%x' % call_to)
                                    skip_this = self.checkVxDirect(call_to, fname)
                                elif self.cpu.architecture.startswith('x86'):
                                    # look for GOT
                                    # ptr -- current sp
                                    # call_to -- destination of call
                                    # cur_fun -- address of current function
                                    # ip_of_call_instruct  -- address of call call instruction
                                    skip_clib = been_above_clib | been_in_main
                                    #self.lgr.debug('stackTrace call checkGOTJump, skip_clib %r' % skip_clib)
                                    skip_this = self.checkGOTJmp(ptr, call_to, cur_fun, fname, ip_of_call_instruct, first_instruct, skip_clib)
                                else:
                                    skip_this = True
                                    self.lgr.debug('stackTrace addr (prev_ip) 0x%x not in fun 0x%x, skip it' % (prev_ip, call_to))
                            else:
                                # inFun returned true
                                #self.lgr.debug('stackTrace is in the function. skip_this is %r' % skip_this)
                                instruct = SIM_disassemble_address(self.cpu, ip_of_call_instruct, 1, 0)
                                fun_hex, fun_name = self.fun_mgr.getFunNameFromInstruction(instruct, ip_of_call_instruct)
                                call_instruction = instruct[1]
                                if fun_hex is None and call_to is not None:
                                    # E.g., call_to found via ARM64 blr analysis artifacts from idaDump
                                    fun_hex = call_to 
                                    fun_name = self.fun_mgr.getFunName(call_to)
                                    call_instruction = call_instruction + ' (%s)' % fun_name
                                ret_addr = ip_of_call_instruct + instruct[0] 
                                frame, adjust_sp = self.genFrame(ip_of_call_instruct, call_instruction, ptr, fun_hex, fun_name, ret_addr, ptr, msg='simple call')
                                ptr = ptr+adjust_sp
                        else:
                            tmp_instruct = SIM_disassemble_address(self.cpu, call_to, 1, 0)
                            self.lgr.debug('stackTrace call_to 0x%x is not a fun, instruct is %s' % (call_to, tmp_instruct[1]))

                            if self.isJmp(tmp_instruct):
                                skip_this = True
                                #self.lgr.debug('stackTrace 0x%x is jump table? skip_this' % call_to)
                            elif self.fun_mgr.isRelocate(call_to):
                                #self.lgr.debug('stackTrace 0x%x is relocatable, but already in main text, assume noise and skip' % call_to)
                                skip_this = True
                            else:
                                #self.lgr.debug('stackTrace 0x%x is not a function?' % call_to)
                                pass
                    else:
                        # call_to is None
                        #self.lgr.debug('stackTrace call to getCallTo was none for ip_of_call_instruct 0x%x' % ip_of_call_instruct)
                        skip_this = False

                ''' The block above assumes we've been in a non-clib type library or main '''
                if ip_of_call_instruct is not None and not skip_this:
                    #self.lgr.debug('stackTrace ip_of_call_instruct 0x%x' % ip_of_call_instruct)
                    skip_this = False
                    instruct = SIM_disassemble_address(self.cpu, ip_of_call_instruct, 1, 0)
                    fun_addr = None 
                    fun_name = None 
                    instruct_str = instruct[1]
                    if self.isCall(instruct_str):
                        # fun_hex and fun are who we think we might be calling
                        fun_hex, fun_name = self.fun_mgr.getFunNameFromInstruction(instruct, ip_of_call_instruct)
                        if fun_name is None and fun_hex is not None and self.top.isVxDKM(cpu=self.cpu):
                            fun_name = self.task_utils.getGlobalSym(fun_hex)
                        self.lgr.debug('stackTrace clean this up, got fun %s for ip_of_call_instruct 0x%x instruct %s cur_fun_name %s ptr 0x%x been_above_clib %r' % (fun_name, ip_of_call_instruct, instruct_str, cur_fun_name, ptr, been_above_clib))
                        #if prev_ip is not None:
                        #    self.lgr.debug('stackTrace prev_ip 0x%x, cur_fun_name %s' % (prev_ip, cur_fun_name))
                        #else:
                        #    self.lgr.debug('stackTrace prev_ip was none, cur_fun_name remains %s' % (cur_fun_name))
                        if fun_name is not None:
                            if ((not self.top.isVxDKM(cpu=self.cpu) and (been_in_main or been_above_clib)) or only_module) and fun_name in dataWatch.mem_funs:
                                #self.lgr.debug('stackTrace function %s is a dataWatch memsomething, but we were already in main or above clib, so bail on it' % fun_name)
                                skip_this = True

                            if cur_fun_name is not None:
                                if not hacked_bp and not self.funMatch(fun_name, cur_fun_name, ip_of_call_instruct, been_above_clib): 
                                    if self.cpu.architecture.startswith('x86'):

                                        if prev_ip is not None and call_to is not None and self.fun_mgr.inFun(prev_ip, call_to, call_ip=ip_of_call_instruct):
                                            #self.lgr.debug('stackTrace candidate x86 function %s does not match current function %s, BUT we think 0x%x is in the fun' % (fun_name, cur_fun_name, prev_ip))
                                            pass
                                        elif been_above_clib or call_to is None or not self.isJumpTable(call_to):
                                            bp = self.mem_utils.getRegValue(self.cpu, 'ebp')
                                            if (bp + self.mem_utils.wordSize(self.cpu)) != ptr:
                                                #self.lgr.debug('stackTrace candidate <%s> does not match <%s> and bp is 0x%x and  ptr is 0x%x skip it' % (fun_name, cur_fun_name, bp, ptr))
                                                count += 1
                                                ptr = ptr + self.mem_utils.wordSize(self.cpu)
                                                continue
                                            #else:
                                            #    self.lgr.debug('stackTrace candidate <%s> does not match <%s> and bp is 0x%x matches  ptr is 0x%x ' % (fun_name, cur_fun_name, bp, ptr))
                                        else:
                                            self.lgr.debug('stackTrace candidate %s maybe reached %s via jump table.' % (fun_name, cur_fun_name))
                                    else:
                                        #self.lgr.debug('stackTrace candidate function %s does not match current function %s, skipit' % (fun_name, cur_fun_name))
                                        ''' don't count this against max frames '''
                                        count += 1
                                        ptr = ptr + self.mem_utils.wordSize(self.cpu)
                                        ''' TBD broken hueristic, e.g., sscanf calls strlen. hack for now... '''
                                        continue
                                #else:
                                #    ''' first frame matches expected function '''
                                #    self.lgr.debug('stackTrace first frame matches expected fun %s, set cur_fun_name to none?' % fun_name)
                                instruct_str = '%s   %s' % (self.callmn, fun_name)
                                #self.lgr.debug('stackTrace instruct_str set to %s' % instruct_str)
                            else:
                                instruct_str = '%s   %s' % (self.callmn, fun_name)
                                #self.lgr.debug('stackTrace no cur_fun_name, instruct_str set to %s' % instruct_str)
                        else:
                            #self.lgr.debug('stackTrace fun was None from instruct %s' % instruct[1])
                            pass
                        fun_fname = None
                        if fun_hex is not None:
                            #self.lgr.debug('stackTrace fun_hex 0x%x, fun_name %s instr %s' % (fun_hex, fun_name, instruct_str))
                            ''' TBD fix for windows '''
                            # TBD what use is this?
                            #if not self.top.isWindows():
                            #    self.soCheck(fun_hex)
                            fun_fname = self.soMap.getSOFileFull(fun_hex)
                            pass
                        else:
                            #self.lgr.debug('stackTrace fun_hex none eh?')
                            if prev_ip is None:
                                #self.lgr.debug('stackTrace fun_hex is none and no prev_ip??? but ip is 0x%x, use that to get fun_hex' % eip)
                                use_ip = eip
                            else:
                                #self.lgr.debug('stackTrace fun_hex none, use_ip from prev_ip 0x%x' % prev_ip)
                                use_ip = prev_ip
                            fun_fname = self.soMap.getSOFileFull(use_ip)
                            if self.fun_mgr is not None:
                                fun_hex = self.fun_mgr.getFun(use_ip)
                                if fun_hex is not None:
                                    fun_name = self.fun_mgr.getFunName(fun_hex)
                                    #self.lgr.debug('stackTrace fun_hex hacked to 0x%x using prev_ip and fun to %s.  TBD generalize this' % (fun_hex, fun_name))
                                    instruct_str = '%s   %s' % (self.callmn, fun_name)
                                    pass
                                #else:
                                #    self.lgr.debug('stackTrace fun_hex hack failed fun_hex still none')
                        fname = self.soMap.getSOFileFull(val)
                        if fname is not None and been_above_clib and resimUtils.isClib(fname):
                            skip_this = True
                        elif fname is None:
                            #print('0x%08x  %-s' % (ip_of_call_instruct, 'unknown'))
                            ret_addr = ip_of_call_instruct + instruct[0] 
                            frame, adjust_sp = self.genFrame(ip_of_call_instruct, instruct_str, ptr, fun_hex, fun_name, ret_addr, ptr, msg='fname is none')
                            ptr = ptr+adjust_sp
                            #self.lgr.debug('stackTrace fname none added frame %s' % frame.dumpString())
                        else:
                            #if self.frames[-1].fun_addr is None:
                            #    self.lgr.error('fun_addr is none')
                            #    SIM_break_simulation('remove this')
                            #    return 
                            #self.lgr.debug('stackTrace (maybe) ADD STACK FRAME FOR 0x%x %s  ptr 0x%x.  prev_ip will become 0x%x fname: %s prev_fname %s called fun fname %s ' % (ip_of_call_instruct, instruct_str, ptr, ip_of_call_instruct, fname, prev_fname, fun_fname))
                            fun_of_call_ip = self.fun_mgr.getFunName(ip_of_call_instruct)
                            #if fun_of_call_ip is not None:
                            #    self.lgr.debug('stackTrace fun_of_call_ip %s' % fun_of_call_ip)
                            #else:
                            #    self.lgr.debug('stackTrace fun_of_call_ip is None')
                            if fun_hex is not None:
                                #self.lgr.debug('stackTrace fun_hex 0x%x' % fun_hex)
                                pass
                            else:
                                fun_hex = self.fun_mgr.getFun(ip_of_call_instruct)
                                #if fun_hex is None:
                                #    self.lgr.debug('stackTrace fun_hex is None')
                                #else:
                                #    self.lgr.debug('stackTrace fun_hex set to 0x%x, TBD why was it not already set?' % fun_hex)

                            if fun_hex in self.black_list:
                                self.lgr.debug('stackTrace call_to 0x%x in blacklist, skip it' % fun_hex)
                                skip_this = True
                             
                            if call_to is not None:
                                if not skip_this:
                                    # TBD low hanging fruit to avoid plt hell
                                    #self.lgr.debug('stackTrace call_to 0x%x prev frame fun name %s fun %s' % (call_to, self.frames[-1].fun_name, fun_name))
                                    if False and self.frames[-1].fun_name is not None and fun == 'close' and 'close' not in self.frames[-1].fun_name.lower():
                                        skip_this = True
                                    else:
                                        call_to_actual, actual_fun = self.checkRelocate(call_to)
                                        if call_to_actual is not None:
                                            actual_fname = self.soMap.getSOFileFull(call_to_actual)
                                            prev_fnamex = self.frames[-1].fname
                                            #self.lgr.debug('stackTrace call_to 0x%x call_to_actual 0x%x fun %s actual_fname %s prev_fnamex %s' % (call_to, call_to_actual, actual_fun, actual_fname, prev_fnamex))
                                            if actual_fname is not None and actual_fname not in [fname, prev_fname]:
                                                skip_this = True 
                            else:
                                call_to_actual = None
                                actual_fun = None
                                #self.lgr.debug('stackTrace call_to is None')
                            ''' ad-hoc detect clib ghost frames, assume clib does not call other libraries.  exceptions?  TBD '''
                            #if fname.startswith('clib'):
                            #    if not prev_fname.startswith('clib') and not prev_fname.startswith('libpthread'):
                            #        #self.lgr.debug('stackTrace found call from clib to 0x%x, assume a ghost frame')
                            #        skip_this = True        
                            if not skip_this and prev_ip is not None and self.soMap.isMainText(val):
                                if not self.soMap.isMainText(prev_ip):
                                    self.lgr.debug('stackTrace val 0x%x in main (%s), prev 0x%x (%s) was not' % (val, fname, prev_ip, prev_fname))
                                    call_instruct = SIM_disassemble_address(self.cpu, ip_of_call_instruct, 1, 0)
                                    self.lgr.debug('stackTrace call instruct %s' % (call_instruct[1]))
                                    if 'bctrl' in call_instruct[1]:
                                        self.lgr.debug('stackTrace bctrl at clib boundary, bail')
                                        skip_this = True
                                    else:
                                        call_to, called_fun_name = self.getCallTo(ip_of_call_instruct)
                                        if call_to is not None:
                                            if called_fun_name is not None:    
                                                # fix call instruction and force function name on called function if it is generic
                                                fun_name = called_fun_name
                                                instruct_str = '%s   %s' % (self.callmn, fun_name)
                                                if self.frames[-1].fun_of_ip is not None and self.frames[-1].fun_of_ip.startswith('sub_'):
                                                    self.frames[-1].fun_of_ip = fun_name
                                            if self.soMap.isMainText(call_to):
                                                #self.lgr.debug('stackTrace prev stack frame was a lib, but we called into main.  If not a PLT, then bail. call-to is 0x%x' % call_to)
                                                if not self.fun_mgr.isRelocate(call_to) and not self.isPLT(call_to):
                                                    skip_this = True
                                                    #self.lgr.debug('stackTrace not a PLT, skipped it first_instruct %s' % first_instruct[1])

                            fname = self.soMap.getSOFileFull(val)
                            if fname is not None and not self.okToCall(fname):
                                #self.lgr.debug('stackTrace ip_of_call_instruct 0x%x NOT OK to call' % ip_of_call_instruct)
                                skip_this = True
                            elif fname is not None:
                                #self.lgr.debug('stackTrace ip_of_call_instruct 0x%x OK to call %s' % (ip_of_call_instruct, fname))
                                #self.lgr.debug('stackTrace fun_of_call_ip %s  fun_name %s  previous fun_of_ip %s' % (fun_of_call_ip, fun_name, self.frames[-1].fun_of_ip)) 
                                # very tenuous
                                if fun_of_call_ip is not None and self.frames[-1].fun_of_ip is not None and fun_of_call_ip.startswith('__') and self.frames[-1].fun_of_ip.startswith('sub_'):
                                    skip_this = True
                                    #self.lgr.debug('stackTrace fun_of_call_ip %s  fun_name %s  previous fun_of_ip %s SKIP IT' % (fun_of_call_ip, fun_name, self.frames[-1].fun_of_ip)) 
                            if not skip_this:
                                if self.cpu.architecture in ['arm', 'arm64', 'ppc32']:
                                    ret_addr = ip_of_call_instruct + 4
                                    #if fun_hex is None:
                                    #    self.lgr.debug('stackTrace FUN HEX NONE')
                                    frame, adjust_sp = self.genFrame(ip_of_call_instruct, instruct_str, ptr, fun_hex, fun_name, ret_addr, None, msg='reasons')
                                else:
                                    #self.lgr.warning('stackTrace NOT setting ret_addr for x86, TBD fun_name %s' % fun_name)
                                    ret_addr = ip_of_call_instruct + instruct[0] 
                                    frame, adjust_sp = self.genFrame(ip_of_call_instruct, instruct_str, ptr, fun_hex, fun_name, ret_addr, ptr)
                                ptr = ptr+adjust_sp
                                #self.lgr.debug('stackTrace fname %s fun is %s added frame %s' % (fname, fun_name, frame.dumpString()))
                            else:
                                pass
                                #self.lgr.debug('stackTrace told to skip %s' % frame.dumpString())
                        if not skip_this:
                            prev_fname = fname
                            #prev_ip = ip_of_call_instruct
                            if self.soMap.isFunNotLibc(ip_of_call_instruct):
                                been_above_clib = True
                                if self.stop_after_clib:
                                    self.lgr.debug('stackTrace been above clib and stop after clib')
                                    done=True 
                            if self.soMap.isMainText(ip_of_call_instruct):
                                been_in_main = True
                                #self.lgr.debug('stackTrace been in main')
                            if self.top.isVxDKM():
                                if not only_module and not self.soMap.inVxWorks(ip_of_call_instruct):
                                    only_module = True
                                    #self.lgr.debug('stackTrace ip_of_call_instruct 0x%x been in main, ignore vxworks funs' % ip_of_call_instruct)
                    else:
                        #self.lgr.debug('doTrace not a call? %s' % instruct_str)
                        ret_addr = ip_of_call_instruct + instruct[0] 
                        frame, adjust_sp = self.genFrame(ip_of_call_instruct, instruct_str, ptr, None, None, ret_addr, None, msg='not a call?')
                        ptr = ptr+adjust_sp
                        #self.lgr.debug('stackTrace not a call? %s fname %s, added frame %s' % (instruct_str, fname, frame.dumpString()))
                else:
                    #self.lgr.debug('nothing from followCall')
                    pass
            elif val is not None and val != 0:
                #self.lgr.debug('ptr 0x%x not code 0x%x' % (ptr, val))
                pass
            count += 1
            ptr = ptr + self.mem_utils.wordSize(self.cpu)
            if self.stack_base is not None and ptr > self.stack_base:
                self.lgr.debug('stackTrace ptr 0x%x > stack_base 0x%x' % (ptr, self.stack_base)) 
                done = True
            elif self.max_frames is not None and len(self.frames)>= self.max_frames:
                #self.lgr.debug('stackFrames got max frames, done max is %d, got %d' % (self.max_frames, len(self.frames)))
                done = True
            elif self.max_bytes is not None and count > self.max_bytes:
                #self.lgr.debug('stackFrames got max bytes %d, done' % self.max_bytes)
                done = True
    
    def checkVxDirect(self, function_addr, fname):
        ''' Does the given funtion have an early direct branch to a vxworks function? '''
        skip_this = True
        pc = function_addr
        for i in range(5):
            instruct = SIM_disassemble_address(self.cpu, pc, 1, 0)
            #self.lgr.debug('stackTrace checkVxDirect, is %s' % instruct[1])
            if instruct[1].startswith('b '):
                parts = instruct[1].split()
                call_to = int(parts[1], 16)
                global_sym = self.task_utils.getGlobalSym(call_to)
                if global_sym is not None:
                    #self.lgr.debug('stackTrace checkVxDirect global sym %s' % global_sym)
                    new_instruct = 'bl %s' % global_sym
                    frame, adjust_sp = self.genFrame(pc, new_instruct, 0, call_to, fun_name, None, None)
                    skip_this = False
                    break
                else:
                    self.lgr.debug('stackTrace checkVxDirect addr 0x%x not global sym' % call_to)
            pc = pc + 4
        return skip_this
         
    def checkArmDirect(self, first_instruct, call_to, prev_ip, ptr, fname, call_ip): 
        skip_this = False
        fun_hex, fun = self.fun_mgr.getFunNameFromInstruction(first_instruct, call_to)
        vx_boundary = False
        if self.top.isVxDKM(cpu=self.cpu) and self.soMap.inVxWorks(prev_ip) and not self.soMap.inVxWorks(fun_hex):
            vx_boundary = True
        self.lgr.debug('stackTrace checkArmDirect direct branch 0x%x %s' % (fun_hex, fun))
        if not (self.fun_mgr.isFun(fun_hex) and self.fun_mgr.inFun(prev_ip, fun_hex)) and not vx_boundary:
            skip_this = True
            self.lgr.debug('stackTrace checkArmDirect addr (prev_ip) 0x%x not in fun 0x%x, or just branch 0x%x skip it' % (prev_ip, call_to, fun_hex))
        else:
            ''' record the direct branch, e.g., B fuFun '''
            ret_addr = call_ip + first_instruct[0] 
            frame, adjust_sp = self.genFrame(call_to, first_instruct[1], ptr, fun_hex, fun, ret_addr, ptr)
            self.lgr.debug('stackTrace checkArmDirect direct branch fname: %s added frame %s' % (fname, frame.dumpString()))
        return skip_this

    def checkGOTJmp(self, ptr, call_to, cur_fun, fname, call_ip, first_instruct, skip_clib):
        skip_this = False
        instruct_of_call = SIM_disassemble_address(self.cpu, call_ip, 1, 0)
        cur_fun_name = self.fun_mgr.getFunName(cur_fun)
        return_addr = self.isGOT(ptr, call_to, cur_fun, cur_fun_name, instruct_of_call, call_ip, fname, False, skip_clib=skip_clib)
        if return_addr is not None:
            #self.lgr.debug('stackTrace was GOT')
            pass
        elif first_instruct[1].lower().startswith('jmp dword') or first_instruct[1].lower().startswith('jmp qword'):
            fun_hex, fun = self.fun_mgr.getFunNameFromInstruction(first_instruct, call_to)
            if not (self.fun_mgr.isFun(fun_hex) and self.fun_mgr.inFun(call_ip, fun_hex)):
                skip_this = True
                #self.lgr.debug('stackTrace addr (prev_ip) 0x%x not in fun 0x%x, or just branch 0x%x skip it' % (prev_ip, call_to, fun_hex))
            else:
                ''' record the direct branch, e.g., jmp dword...'''
                ret_addr = call_ip + first_instruct[0] 
                frame, adjust_sp = self.genFrame(call_to, first_instruct[1], ptr, fun_hex, fun, ret_addr, ptr)
                self.lgr.debug('stackTrace direct branch fname: %s added frame %s' % (fname, frame.dumpString()))
        else:
            bp = self.mem_utils.getRegValue(self.cpu, 'ebp')
            if (bp + self.mem_utils.wordSize(self.cpu)) != ptr:
                skip_this = True
                #self.lgr.debug('stackTrace addr (prev_ip) 0x%x not in fun 0x%x, and bp is 0x%x and  ptr is 0x%x skip it' % (prev_ip, call_to, bp, ptr))
        return skip_this


    def checkRelocate(self, eip):
        fun_hex = None
        fun = None
        first_instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        #self.lgr.debug('stackTrace checkRelocate first instruct %s ip 0x%x' % (first_instruct[1], eip))
        if first_instruct[1].startswith('jmp'):
            fun_hex, fun = self.fun_mgr.getFunNameFromInstruction(first_instruct, eip)
        return fun_hex, fun

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
                    full = self.top.getAnalysisPath(fname)
                    self.lgr.debug('stackTrace soCheck eip 0x%x not a fun? Adding it.  fname %s full %s start 0x%x' % (eip, fname,full, start))
                    self.fun_mgr.add(full, start)
            self.fun_mgr.soCheckAdd(eip) 

    def countFrames(self):
        return len(self.frames)

    def genFrame(self, called_from_address, instruction, stack_ptr, called_to_address, called_fun_name, return_addr, addr_of_ret_addr, msg=''):
        fname = self.soMap.getSOFile(called_from_address)
        if fname is None:
            fname = 'unknown'
        if called_to_address is None:
            called_to_address = self.fun_mgr.getFunEntry(called_fun_name)
        frame = self.FrameEntry(called_from_address, fname, instruction, stack_ptr, fun_addr=called_to_address, fun_name=called_fun_name, 
                               ret_addr=return_addr, ret_to_addr=addr_of_ret_addr)
        adjust_sp = self.addFrame(frame)
        self.lgr.debug('stackTrace genFrame %s -- adjust: 0x%x called_fun_name %s frame: %s' % (msg, adjust_sp, called_fun_name, frame.dumpString()))
        return frame, adjust_sp

    def addFrame(self, frame):
        adjust = 0
        prev_ip = None
        fun_of_prev_ip = None
        if len(self.frames) > 0:
            prev_ip = self.frames[-1].ip
            fun_of_prev_ip = self.frames[-1].fun_name
            #self.lgr.debug('stackTrace addFrame fun_of_prev_ip %s, this one %s' % (fun_of_prev_ip, frame.fun_name))
        if self.skip_recurse and frame.fun_name is not None and frame.fun_name == fun_of_prev_ip:
            self.lgr.debug('stackTrace addFrame function same as last function, skip_recurse is true, skip it')
            pass
        elif frame.ip != prev_ip:
            if self.fun_mgr is not None:
                fun_of_ip = self.fun_mgr.getFunName(frame.ip)
                frame.fun_of_ip = fun_of_ip
                frame.fun_addr_of_ip = self.fun_mgr.getFun(frame.ip)
                #self.lgr.debug('stackTrace addFrame set fun_of_ip to %s frame.ip 0x%x' % (fun_of_ip, frame.ip))

                if self.isCall(frame.instruct):
                    parts = frame.instruct.split()
                    call_addr = None
                    if len(parts) == 2:
                        try:
                            call_addr = int(parts[1],16)
                        except ValueError:
                            pass
                        if call_addr is not None:
                            fun = self.fun_mgr.getFunName(call_addr)
                            if fun is not None:
                                frame.instruct = '%s %s' % (self.callmn, fun)                     
                            elif self.top.isVxDKM(cpu=self.cpu):
                                #self.lgr.debug('stackTrace addFrame is vxdkm')
                                fun = self.task_utils.getGlobalSym(call_addr)
                                if fun is not None:
                                    frame.instruct = '%s %s' % (self.callmn, fun)                     
                                    frame.fun_name = fun 
                        if self.decode.isReg(parts[1]):
                            self.lgr.debug('stackTrace addFrame call to reg %s' % parts[1])
                            call_reg = self.fun_mgr.getBlr(frame.ip)
                            if call_reg is not None:
                                frame.instruct = '%s %s' % (self.callmn, call_reg)
                                frame.fun_name = call_reg
                            elif len(self.frames) > 1:
                                self.lgr.debug('stackTrace addFrame previous fname is %s fun of ip %s' % (self.frames[-1].fname, self.frames[1].fun_of_ip))
                                if resimUtils.isClib(self.frames[-1].fname) and not resimUtils.isClib(frame.fname):
                                    frame.instruct = '%s %s' % (self.callmn, self.frames[-1].fun_of_ip)
                                    frame.fun_name = self.frames[1].fun_of_ip
                    else:
                        call_reg = self.fun_mgr.getBlr(frame.ip)
                        if call_reg is not None:
                            frame.instruct = '%s %s' % (self.callmn, call_reg)
                            frame.fun_name = call_reg
        
            skip_this = False
            if frame.fun_name is None and frame.fun_addr is not None:
                #self.lgr.debug('stackTrace addFrame given fun_name is None for fun_addr 0x%x, last chance texeco' % frame.fun_addr)
                fun = self.fun_mgr.getFunName(frame.fun_addr)
                if fun is not None:
                    frame.fun_name = fun
                elif self.top.isVxDKM(cpu=self.cpu):
                    fun = self.task_utils.getGlobalSym(frame.fun_addr)
                    if fun is not None:
                        frame.fun_name = fun
                    else:
                        skip_this=True
                        self.lgr.debug('stackTrace addFrame vxworks fun_addr 0x%x not a fun, bail' % frame.fun_addr)
            if not skip_this:
                # adjust is confusing because we adjust on the next frame.  consider ldp x1,x2, [sp], #36  before changing.
                if self.cpu.architecture in ['arm', 'arm64']:
                    adjust = self.fun_mgr.stackAdjust(frame.fun_name)
                    self.lgr.debug('stackTrace addFrame arm get adjust for fun %s got %d' % (frame.fun_name, adjust))
                else:
                    adjust = self.fun_mgr.stackAdjust(frame.fun_of_ip)
                    self.lgr.debug('stackTrace addFrame get adjust for fun %s got %d' % (frame.fun_of_ip, adjust))
                self.frames.append(frame)
                #self.lgr.debug('stackTrace addFrame %s' % frame.dumpString())
                self.prev_frame_sp = frame.sp
                if len(self.frames) > self.most_frames:
                    self.most_frames = len(self.frames)
                    self.best_frames = list(self.frames[:-1])
                if len(self.frames) > 1:
                    #self.lgr.debug('stackTrace addFrame now %d frames fname %s prev fname %s' % (len(self.frames), self.frames[-1].fname, self.frames[-2].fname))
                    if self.frames[-1].fname is not None and self.frames[-2].fname is not None and self.frames[-1].fname != self.frames[-2].fname:
                       # recent frame was a library boundary
                       delta =  (self.frames[-1].sp - self.frames[-2].sp) 
                       #self.lgr.debug('stackTrace addFrame sp 0x%x and 0x%x delta %d' % (self.frames[-1].sp, self.frames[-2].sp, delta))
                       if (self.frames[-1].sp - self.frames[-2].sp) > 1500:
                           self.mind_the_gap = True
                           self.lgr.debug('stackTrace addFrame found a gap of %d' % delta)
            else:
                self.lgr.debug('stackTrace skipping for vxworks reasons')
        else:
            self.lgr.debug('stackTrace skipping back to back identical calls: %s' % frame.instruct)
            pass
        #adjust = 0
        if adjust > 0:
            # obscure to simplify code in doTrace.  Will need to put the word back in functions such as isCallToMe
            adjust = adjust - self.word_size
            #self.lgr.debug('stackTrace addFrame, adjust SP by 0x%x' % adjust)
        return adjust
       
    def readAppPtr(self, addr):
        if self.word_size == 4: 
            retval = self.mem_utils.readWord32(self.cpu, addr)
        else:
            retval = self.mem_utils.readWord(self.cpu, addr)
        return retval

    def hackBP(self, ptr, fname):
        retval = None
        bp = self.mem_utils.getRegValue(self.cpu, 'rbp')
        self.lgr.debug('stackTrace bp hack check bp is 0x%x  ptr 0x%x' % (bp, ptr))
        done = False
        new_ptr = ptr
        while not done:
            if bp > new_ptr and (bp - new_ptr) < 0xa00 and resimUtils.isClib(fname):
                prev_addr = bp - self.word_size
                prev_fun_ip = self.mem_utils.readWord(self.cpu, prev_addr)
                prev_fun = self.fun_mgr.getFunName(prev_fun_ip)
                if prev_fun is None: 
                    self.lgr.debug('stackTrace hackBP read prev_fun_ip 0x%x from prev_addr 0x%x, not a fun, bail' % (prev_fun_ip, prev_addr))
                    done = True
                    break
                self.lgr.debug('stackTrace hackBP setting new_ptr to bp 0x%x' % bp)
                new_ptr = bp 
                retval = new_ptr
                next_addr = new_ptr + self.word_size
                bp = self.mem_utils.readWord(self.cpu, next_addr)
                self.lgr.debug('stackTrace hackBP read new bp of 0x%x from next_addr 0x%x' % (bp, next_addr))
            else:
                self.lgr.debug('stackTrace hackBP fails test bp 0x%x new_ptr 0x%x' % (bp, new_ptr))
                done = True
        if retval is not None:
            self.lgr.debug('stackTrace hackBP returning new ptr 0x%x' % retval)
        return retval

    def isJumpTable(self, call_to):
        retval = False
        ip = call_to
        instruct = SIM_disassemble_address(self.cpu, ip, 1, 0)
        self.lgr.debug('stackTrace isJumpTable ip 0x%x instruct %s' % (ip, instruct[1]))
        ip = ip + instruct[0]
        for i in range(5):
            if instruct[1].startswith('jmp'):
                parts = instruct[1].split()
                if len(parts) == 2 and self.decode.isReg(parts[1]):
                    self.lgr.debug('stackTrace isJumpTable IS A JUMP ip 0x%x instruct %s' % (ip, instruct[1]))
                    retval = True
                    break
            ip = ip + instruct[0]
            instruct = SIM_disassemble_address(self.cpu, ip, 1, 0)
        return retval

    def mindTheGap(self, ptr):
       retval = False
       if self.frames[-1].fname is not None and resimUtils.isClib(self.frames[-1].fname) and (ptr - self.prev_frame_sp) > 2000:
           retval = True
       return retval

    def recordVxCall(self, pc):
        # record what looks like a call to VxWorks, if the call seems to be from base on the lr register
        lr = self.reg_frame['lr']
        module = self.soMap.getSOFile(lr)
        if lr == pc or (lr+4) == pc:
            self.lgr.debug('stackTrace recordVxCall lr reflects recent return')
        elif module is not None:
            self.lgr.debug('stackTrace recordVxCall in module %s' % module)
            call_pc = lr - 4
            instruct = self.top.disassembleAddress(self.cpu, call_pc)
            self.lgr.debug('stackTrace recordVxCall  call instruct is %s' % instruct[1])
            if instruct[1].startswith('bl'):
                parts = instruct[1].split()
                #call_to = int(parts[1], 16)
                call_to = self.decode.getValue(parts[1], self.cpu)
                global_sym = self.task_utils.getGlobalSym(call_to)
                if global_sym is not None:
                    self.lgr.debug('stackTrace recordVxCall global sym %s' % global_sym)
                    new_instruct = 'bl %s' % global_sym
                    frame, adjust_sp = self.genFrame(call_pc, new_instruct, 0, call_to, global_sym, lr, None)
                else:
                    fun_name = self.fun_mgr.getFunName(call_to)
                    new_instruct = 'bl %s' % fun_name
                    self.lgr.debug('stackTrace recordVxCall addr 0x%x not global sym, is module fun %s' % (call_to, fun_name))
                    frame, adjust_sp = self.genFrame(call_pc, new_instruct, 0, call_to, fun_name, lr, None)
            else:
                self.lgr.debug('stackTrace recordVxCall not a call?')
        elif not self.soMap.inVxWorks(lr):
            self.lgr.debug('stackTrace recordVxCall 0x%x not in module or vxworks?' % lr)
        else:
            self.lgr.debug('stackTrace recordVxCall lr 0x%x is in vxWorks' % lr)
        return module

    def windowsBP(self, ptr, fname):
        # Should we adjust ptr per the bp register?
        # Just look for a leave instruction 
        if fname is not None:
            self.lgr.debug('***FIX THIS, should know what function we are in and then check for leave')
        else:
            # why this funtion was added in the first place
            pass
        retval = None
        esp = self.reg_frame['sp']
        bp = self.mem_utils.getRegValue(self.cpu, 'ebp')
        eip = self.reg_frame['pc']
        self.lgr.debug('stackTrace windowsBP ptr 0x%x fname %s bp 0x%x esp 0x%x ip 0x%x' % (ptr, fname, bp, esp, eip))
        instruct = None
        for i in range(30):
            instruct = self.top.disassembleAddress(self.cpu, eip)
            #self.lgr.debug('stackTrace windowsBP instruct %s' % instruct[1])
            if instruct[1] == 'leave':
                self.lgr.debug('stackTrace windowsBP found leave, use bp')
                retval = bp 
                break
            elif instruct[1] == 'ret':
                break
            eip = eip + instruct[0]
        return retval

    def okToCall(self, fname):
        ''' should the so lib named by fname be calling the previous stack frame? '''
        retval = True
        if fname is not None:
            fname_index = resimUtils.getClibIndex(fname)
            prev_index = resimUtils.getClibIndex(self.frames[-1].fname)
            if fname_index is not None and prev_index is not None:
                if fname_index < prev_index:
                    #self.lgr.debug('stackTrace okToCall fname %s should not be calling %s' % (fname, self.frames[-1].fname))
                    retval = False
                #else:
                #    self.lgr.debug('stackTrace okToCall fname %s (index %d) OK calling %s (index %d)' % (fname, fname_index, self.frames[-1].fname, prev_index))
            #elif fname_index is None:
            #    self.lgr.debug('stackTrace okToCall fname_index none for fname %s' % fname)
            #elif prev_index is None:
            #    self.lgr.debug('stackTrace okToCall prev_index none for prev fame %s' % self.frames[-1].fname)
        return retval


