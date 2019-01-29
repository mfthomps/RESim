from simics import *
import json
class StackTrace():
    class FrameEntry():
        def __init__(self, ip, fname, instruct):
            self.ip = ip
            self.fname = fname
            self.instruct = instruct

    def __init__(self, top, cpu, pid, soMap, mem_utils, task_utils, stack_base, lgr):
        self.top = top
        self.cpu = cpu
        self.pid = pid
        self.lgr = lgr
        self.soMap = soMap
        self.frames = []
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.stack_base = stack_base


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
        fname = self.soMap.getSOFile(self.pid, eip)
        #print('0x%08x  %-s' % (eip, fname))
        frame = self.FrameEntry(eip, fname, '')
        self.frames.append(frame)
        done  = False
        count = 0
        #ptr = ebp
        ptr = esp
        been_in_main = False
        while not done and count < 9000: 
            val = self.mem_utils.readPtr(self.cpu, ptr)
            skip_this = False
                
            if self.soMap.isCode(self.pid, val):
                self.lgr.debug('is code: 0x%x from ptr 0x%x' % (val, ptr))
                call_ip = self.followCall(val)
                if been_in_main and not self.soMap.isMainText(self.pid, val):
                    ''' once in main text assume we never leave? what about callbacks?'''
                    skip_this = True
                if call_ip is not None and not skip_this:
                    skip_this = False
                    instruct = SIM_disassemble_address(self.cpu, call_ip, 1, 0)[1]
                    self.lgr.debug('followCall call_ip 0x%x %s' % (call_ip, instruct))
                    fname = self.soMap.getSOFile(self.pid, val)
                    if fname is None:
                        #print('0x%08x  %-s' % (call_ip, 'unknown'))
                        frame = self.FrameEntry(call_ip, 'unknown', instruct)
                        self.frames.append(frame)
                    else:
                        #print('0x%08x  %-s' % (call_ip, fname))
                        frame = self.FrameEntry(call_ip, fname, instruct)
                        self.frames.append(frame)
                    if self.soMap.isMainText(self.pid, call_ip):
                        been_in_main = True
                        self.lgr.debug('stackTrace been in main')
                    ''' value at ptr-word_size should be ebp '''
                    '''
                    ebp = self.mem_utils.readPtr(self.cpu, ptr-self.mem_utils.WORD_SIZE)
                    if ebp == 0:
                        done = True
                    else:
                        ptr = ebp - 2*self.mem_utils.WORD_SIZE
                    self.lgr.debug('ptr: 0x%x ebp: 0x%x' % (ptr, ebp))
                    '''
                else:
                    self.lgr.debug('nothing from followCall')
            else:
                #self.lgr.debug('not code 0x%x' % val)
                pass
            count += 1
            ptr = ptr + self.mem_utils.WORD_SIZE
            if self.stack_base is not None and ptr > self.stack_base:
                done = True
