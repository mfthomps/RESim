from simics import *
import json
import os
import memUtils
class StackTrace():
    class FrameEntry():
        def __init__(self, ip, fname, instruct, sp, ret_addr=None, fun_addr=None, fun_name=None):
            self.ip = ip
            self.fname = fname
            self.instruct = instruct
            self.sp = sp
            self.ret_addr = ret_addr
            self.fun_addr = fun_addr
            self.fun_name = fun_name
            self.fun_of_ip = None
        def dumpString(self):
            if self.ret_addr is not None:
                return 'ip: 0x%x fname: %s instruct: %s sp: 0x%x ret_addr: 0x%x' % (self.ip, self.fname, self.instruct, self.sp, self.ret_addr)
            else:
                return 'ip: 0x%x fname: %s instruct: %s sp: 0x%x ' % (self.ip, self.fname, self.instruct, self.sp)

    def __init__(self, top, cpu, pid, soMap, mem_utils, task_utils, stack_base, ida_funs, targetFS, 
                 relocate_funs, reg_frame, lgr, max_frames=None, max_bytes=None):
        self.top = top
        self.cpu = cpu
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
            
    def isArmCall(self, instruct):
        retval = False
        if instruct.startswith(self.callmn):
            retval = True
        elif instruct.startswith('ldr'):
            parts = instruct.split()
            if parts[1].strip().lower() == 'pc,':
               retval = True
        return retval
            
    def followCall(self, return_to):
        retval = None
        if self.cpu.architecture == 'arm':
            #self.lgr.debug('followCall return_to 0x%x' % return_to)
            eip = return_to - 4
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            #self.lgr.debug('followCall instruct is %s' % instruct[1])
            if self.isArmCall(instruct[1]):
                #self.lgr.debug('followCall arm eip 0x%x' % eip)
                retval = eip
        else:
            eip = return_to - 2*(self.mem_utils.WORD_SIZE)
            # TBD use instruction length to confirm it is a true call
            # not always 2* word size?
            while retval is None and eip < return_to:
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                #self.lgr.debug('stackTrace followCall instruct %s' % instruct[1])
                if instruct[1].startswith(self.callmn):
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
                            eip = eip+1
                    else:        
                        retval = eip
                else:
                    eip = eip+1
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
            fun_addr = self.ida_funs.getFun(frame.ip)
            fun_of_ip = self.ida_funs.getName(fun_addr)
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
                print('%s 0x%08x %s %s %s' % (sp_string, frame.ip, fname, frame.instruct, fun_of_ip))

    def funFromAddr(self, addr):
        fun = None
        if addr in self.relocate_funs:
            fun = self.relocate_funs[addr]
        elif self.ida_funs is not None:
            fun = self.ida_funs.getName(addr)
        return fun

    def getFunName(self, instruct):
        ''' get the called function address and its name, if known '''
        parts = instruct.split()
        if len(parts) != 2:
            self.lgr.debug('stackTrace getFunName not a call? %s' % instruct)
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
                        self.lgr.debug('StackTrace isCallToMe could not get instruct from 0x%x' % call_instr)
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
                                self.lgr.debug('fun is None')
                                if fun_hex in self.relocate_funs:
                                    fun = self.relocate_funs[fun_hex]
                                    new_instruct = '%s   0x%x' % (self.callmn, fun)
                                    #self.lgr.debug('fun relocate %s' % fun)
                                else:
                                    #self.lgr.debug('fun_hex is 0x%x' % fun_hex)
                                    new_instruct = '%s   0x%x' % (self.callmn, fun_hex)
                            frame = self.FrameEntry(call_instr, fname, new_instruct, 0, ret_addr=lr, fun_addr=fun_hex, fun_name = fun)
                            self.addFrame(frame)
                            #self.lgr.debug('isCallToMe adding frame %s' % frame.dumpString())
                            retval = lr
                        elif fun_hex is not None:
                            ''' LR does not suggest call to current function. Is current a different library then LR? '''
                            #self.lgr.debug('try got')
                            if self.tryGot(lr, eip, fun_hex):
                                new_instruct = '%s   %s' % (self.callmn, fun)
                                call_fname, dumb1, dumb2 = self.soMap.getSOInfo(call_instr)
                                frame = self.FrameEntry(call_instr, call_fname, new_instruct, 0, ret_addr=lr, fun_addr=fun_hex, fun_name = fun)
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
            self.lgr.debug('1st %s 2nd %s' % (instruct[1], second_instruct[1]))
            parts = second_instruct[1].split()
            if parts[0].upper() == "LDR" and parts[2].upper() == "PC,":
                self.lgr.debug("2nd instruction of 0x%x is ldr pc" % fun_hex)
                retval = True
            else:
                third_fun_eip = fun_hex + instruct[0]+second_instruct[0]
                third_instruct = SIM_disassemble_address(self.cpu, third_fun_eip, 1, 0)
                self.lgr.debug('3nd %s' % (third_instruct[1]))
                parts = third_instruct[1].split()
                if parts[0].upper() == "LDR" and parts[1].upper() == "PC,":
                    self.lgr.debug("3nd instruction of 0x%x is ldr pc" % fun_hex)
                    retval = True
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
        if instruct.startswith(self.callmn):
            parts = instruct.split()
            try:
                faddr = int(parts[1], 16)
                #print('faddr 0x%x' % faddr)
                fun_name = None
                if self.ida_funs is not None:
                    fun_name = self.ida_funs.getName(faddr)
                if fun_name is not None:
                    instruct = '%s %s' % (self.callmn, fun_name)
            except ValueError:
                pass


        #self.lgr.debug('StackTrace doTrace begin cur eip 0x%x instruct %s  fname %s' % (eip, instruct, fname))
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
            #self.lgr.debug('doTrace starting eip: 0x%x is in fun %s 0x%x' % (eip, cur_fun_name, cur_fun))
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
                                self.lgr.debug('so check of %s the call_to of 0x%x not in IDA funs?' % (fname, call_to))
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
                                self.lgr.debug('stackTrace 0x%x is jump table?' % call_to)
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
                                if not (fun.startswith(cur_fun_name) or cur_fun_name.startswith(fun)):
                                    if self.cpu.architecture != 'arm':
                                        bp = self.mem_utils.getRegValue(self.cpu, 'ebp')
                                        if (bp + self.mem_utils.WORD_SIZE) != ptr:
                                            self.lgr.debug('StackTrace candidate <%s> does not match <%s> and bp is 0x%x and  ptr is 0x%x skip it' % (fun, cur_fun_name, bp, ptr))
                                            count += 1
                                            ptr = ptr + self.mem_utils.WORD_SIZE
                                            cur_fun_name = None
                                            continue
                                        else:
                                            cur_fun_name = None
                                    else:
                                        self.lgr.debug('stackTrace candidate function %s does not match current function %s, skipit' % (fun, cur_fun_name))
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
                            self.lgr.debug('stackTrace fname none added frame %s' % frame.dumpString())
                        else:
                            ''' ad-hoc detect clib ghost frames, assume clib does not call other libraries.  exceptions?  TBD '''
                            if fname.startswith('clib'):
                                if not prev_fname.startswith('clib') and not prev_fname.startswith('libpthread'):
                                    #self.lgr.debug('stackTrace found call from clib to 0x%x, assume a ghost frame')
                                    skip_this = True        
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
                self.lgr.debug('stackTrace ptr 0x%x > stack_base 0x%x' % (ptr, self.stack_base)) 
                done = True
            elif self.max_frames is not None and len(self.frames)>= self.max_frames:
                self.lgr.debug('stackFrames got max frames, done max is %d, got %d' % (self.max_frames, len(self.frames)))
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
                self.lgr.debug('stackTrace soCheck eip 0x%x not a fun? Adding it.  fname %s full %s start 0x%x' % (eip, fname,full, start))
                self.ida_funs.add(full, start)

    def countFrames(self):
        return len(self.frames)

    def addFrame(self, frame):
        prev_instruct = ''
        if len(self.frames) > 0:
            prev_instruct = self.frames[-1].instruct
        if self.ida_funs is not None and frame.instruct != prev_instruct:
            fun_addr = self.ida_funs.getFun(frame.ip)
            fun_of_ip = self.ida_funs.getName(fun_addr)
            frame.fun_of_ip = fun_of_ip
            self.frames.append(frame)
        else:
            self.lgr.debug('stackTrace skipping back to back identical calls: %s' % frame.instruct)
        
