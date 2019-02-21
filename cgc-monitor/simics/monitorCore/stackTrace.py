from simics import *
import json
class StackTrace():
    class FrameEntry():
        def __init__(self, ip, fname, instruct):
            self.ip = ip
            self.fname = fname
            self.instruct = instruct

    def __init__(self, top, cpu, pid, soMap, mem_utils, task_utils, stack_base, ida_funs, lgr):
        self.top = top
        self.cpu = cpu
        self.pid = pid
        self.lgr = lgr
        self.soMap = soMap
        self.frames = []
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.stack_base = stack_base
        self.ida_funs = ida_funs

        self.doTrace()

    def followCall(self, return_to):
        eip = return_to - 8
        retval = None
        # TBD use instruction length to confirm it is a true call
        while retval is None and eip < return_to:
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            if instruct[1].startswith('call'):
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

    def printTrace(self):
        for frame in self.frames:
            print('0x%08x %s %s' % (frame.ip, frame.fname, frame.instruct))

    def doTrace(self):
        esp = self.mem_utils.getRegValue(self.cpu, 'esp')
        self.lgr.debug('stackTrace doTrace esp is 0x%x' % esp)
        #ebp = self.mem_utils.getRegValue(self.cpu, 'ebp')
        #if ebp == 0:
        #    ''' we just returned and bp is on stack '''
        #    ebp = esp
        #    self.lgr.debug('stackTrace doTrace ebp was zero, setting to esp')
        eip = self.top.getEIP(self.cpu)
        fname = self.soMap.getSOFile(eip)
        #print('0x%08x  %-s' % (eip, fname))
        frame = self.FrameEntry(eip, fname, '')
        self.frames.append(frame)
        done  = False
        count = 0
        #ptr = ebp
        ptr = esp
        been_in_main = False
        prev_ip = None
        if self.soMap.isMainText(eip):
            been_in_main = True
            prev_ip = eip
        while not done and count < 9000: 
            val = self.mem_utils.readPtr(self.cpu, ptr)
            skip_this = False
                
            if self.soMap.isCode(val):
                call_ip = self.followCall(val)
                if call_ip is not None:
                   #self.lgr.debug('is code: 0x%x from ptr 0x%x   call_ip 0x%x' % (val, ptr, call_ip))
                   pass
                if been_in_main and not self.soMap.isMainText(val):
                    ''' once in main text assume we never leave? what about callbacks?'''
                    skip_this = True
                if been_in_main and self.ida_funs is not None and call_ip is not None and prev_ip is not None:
                    instruct = SIM_disassemble_address(self.cpu, call_ip, 1, 0)[1]
                    call_to_s = instruct.split()[1]
                    call_to = None
                    #self.lgr.debug('stackTrace check call to %s' % call_to_s)
                    try:
                        call_to = int(call_to_s, 16)
                    except:
                        pass 
                    if call_to is not None and self.ida_funs.isFun(call_to):
                        if not self.ida_funs.inFun(prev_ip, call_to):
                            skip_this = True
                            #self.lgr.debug('StackTrace addr 0x%x not in fun 0x%x, skip it' % (prev_ip, call_to))
                    elif call_to is not None:
                        tmp_instruct = SIM_disassemble_address(self.cpu, call_to, 1, 0)[1]
                        if tmp_instruct.startswith('jmp'):
                            skip_this = True
                            #self.lgr.debug('stackTrace 0x%x is jump table?' % call_to)
                        else:
                            #self.lgr.debug('stackTrace 0x%x is not a function?' % call_to)
                            pass
 
                if call_ip is not None and not skip_this:
                    skip_this = False
                    instruct = SIM_disassemble_address(self.cpu, call_ip, 1, 0)[1]
                    #self.lgr.debug('followCall call_ip 0x%x %s' % (call_ip, instruct))
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
                    #self.lgr.debug('nothing from followCall')
                    pass
            else:
                #self.lgr.debug('not code 0x%x' % val)
                pass
            count += 1
            ptr = ptr + self.mem_utils.WORD_SIZE
            if self.stack_base is not None and ptr > self.stack_base:
                self.lgr.debug('stackTrace ptr 0x%x > stack_base 0x%x' % (ptr, self.stack_base)) 
                done = True
