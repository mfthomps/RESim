from simics import *
import json
import os
class StackTrace():
    class FrameEntry():
        def __init__(self, ip, fname, instruct):
            self.ip = ip
            self.fname = fname
            self.instruct = instruct

    def __init__(self, top, cpu, pid, soMap, mem_utils, task_utils, stack_base, ida_funs, targetFS, lgr):
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
        if cpu.architecture == 'arm':
            self.callnm = 'bl'
            self.jmpnm = 'bx'
        else:
            self.callnm = 'call'
            self.jmpnm = 'jmp'

        self.doTrace()

    def followCall(self, return_to):
        retval = None
        if self.cpu.architecture == 'arm':
            eip = return_to - 4
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            if instruct[1].startswith(self.callnm):
                parts = instruct[1].split()
                if len(parts) == 2:
                    try:
                        dst = int(parts[1],16)
                    except:
                        retval = eip
                        return retval
                    if self.soMap.isCode(dst):
                        retval = eip
                else:        
                    retval = eip
        else:
            eip = return_to - 2*(self.mem_utils.WORD_SIZE)
            # TBD use instruction length to confirm it is a true call
            # not always 2* word size?
            while retval is None and eip < return_to:
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                if instruct[1].startswith(self.callnm):
                    parts = instruct[1].split()
                    if len(parts) == 2:
                        try:
                            dst = int(parts[1],16)
                        except:
                            retval = eip
                            continue
                        if self.soMap.isCode(dst):
                            retval = eip
                        else:
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
            retval.append(item)
        return json.dumps(retval)

    def getFrames(self, count):
        retval = []
        for i in range(count):
            retval.append(self.frames[i])
        return retval

    def getFrameIPs(self):
        retval = []
        for f in self.frames:
            retval.append(f.ip)
        return retval

    def printTrace(self):
        for frame in self.frames:
            print('0x%08x %s %s' % (frame.ip, frame.fname, frame.instruct))

    def doTrace(self):
        esp = self.mem_utils.getRegValue(self.cpu, 'esp')
        self.lgr.debug('stackTrace doTrace esp is 0x%x' % esp)
        eip = self.top.getEIP(self.cpu)
        fname = self.soMap.getSOFile(eip)
        #print('0x%08x  %-s' % (eip, fname))
        frame = self.FrameEntry(eip, fname, '')
        self.frames.append(frame)
        done  = False
        count = 0
        #ptr = ebp
        ptr = esp
        #ptr = esp + self.mem_utils.WORD_SIZE
        been_in_main = False
        prev_ip = None
        so_checked = []
        if self.soMap.isMainText(eip):
            self.lgr.debug('stackTrace starting in main text')
            been_in_main = True
            prev_ip = eip
        #prev_ip = eip
        if self.ida_funs is None:
            self.lgr.warning('stackTrace has no ida functions')

        ''' record info about current IP '''
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)[1]
        fname = self.soMap.getSOFile(eip)
        self.lgr.debug('cur eip 0x%x instruct %s  fname %s' % (eip, instruct, fname))
        if fname is None:
            frame = self.FrameEntry(eip, 'unknown', instruct)
            self.frames.append(frame)
        else:
            frame = self.FrameEntry(eip, fname, instruct)
            self.frames.append(frame)

        while not done and (count < 9000): 
            val = self.mem_utils.readPtr(self.cpu, ptr)
            # TBD should be part of readPtr?
            if self.mem_utils.WORD_SIZE == 8:
                val = val & 0x0000ffffffffffff
            skip_this = False
                
            if self.soMap.isCode(val):
                call_ip = self.followCall(val)
                if call_ip is not None:
                   self.lgr.debug('is code: 0x%x from ptr 0x%x   call_ip 0x%x' % (val, ptr, call_ip))
                   pass
                else:
                   self.lgr.debug('is code not follow call: 0x%x from ptr 0x%x   ' % (val, ptr))
                   
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
                                #self.lgr.debug('so checj of %s' % fname)
                                if fname is not None:
                                    full_path = self.targetFS.getFull(fname)
                                    self.ida_funs.add(full_path, start)
                            so_checked.append(call_to) 
                        if self.ida_funs.isFun(call_to):
                            if not self.ida_funs.inFun(prev_ip, call_to):
                                skip_this = True
                                #self.lgr.debug('StackTrace addr 0x%x not in fun 0x%x, skip it' % (prev_ip, call_to))
                        else:
                            tmp_instruct = SIM_disassemble_address(self.cpu, call_to, 1, 0)[1]
                            if tmp_instruct.startswith(self.jmpnm):
                                skip_this = True
                                #self.lgr.debug('stackTrace 0x%x is jump table?' % call_to)
                            else:
                                #self.lgr.debug('stackTrace 0x%x is not a function?' % call_to)
                                pass
 
                if call_ip is not None and not skip_this:
                    skip_this = False
                    instruct = SIM_disassemble_address(self.cpu, call_ip, 1, 0)[1]
                    self.lgr.debug('followCall call_ip 0x%x %s' % (call_ip, instruct))
                    fname = self.soMap.getSOFile(val)
                    if fname is None:
                        #print('0x%08x  %-s' % (call_ip, 'unknown'))
                        frame = self.FrameEntry(call_ip, 'unknown', instruct)
                        self.frames.append(frame)
                    else:
                        #print('0x%08x  %-s' % (call_ip, fname))
                        frame = self.FrameEntry(call_ip, fname, instruct)
                        self.frames.append(frame)
                    prev_ip = call_ip
                    if self.soMap.isMainText(call_ip):
                        been_in_main = True
                        #self.lgr.debug('stackTrace been in main')
                else:
                    self.lgr.debug('nothing from followCall')
                    pass
            elif val is not None:
                #self.lgr.debug('ptr 0x%x not code 0x%x' % (ptr, val))
                pass
            count += 1
            ptr = ptr + self.mem_utils.WORD_SIZE
            if self.stack_base is not None and ptr > self.stack_base:
                self.lgr.debug('stackTrace ptr 0x%x > stack_base 0x%x' % (ptr, self.stack_base)) 
                done = True


    def soCheck(self, eip):

        ''' should we add ida function analysis? '''
        if self.ida_funs is not None and not self.ida_funs.isFun(eip):
            fname, start, end = self.soMap.getSOInfo(eip)
            if fname is not None:
                full = self.targetFS.getFull(fname)
                self.lgr.debug('so check of %s full %s' % (fname,full))
                self.ida_funs.add(full, start)


    def countFrames(self):
        return len(self.frames)
