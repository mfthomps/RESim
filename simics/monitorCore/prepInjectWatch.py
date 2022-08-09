import os
import pickle
import stopFunction
import watchMarks
from simics import *
import decode
import decodeArm
import resimUtils
'''
Create a snapshot from a given watch mark index value, intended to
be an ioctl.  The snapshot will preceed the ioctl call, and
will include the address of the kernel buffer, and the kernel pointers
used ot calculate the ioctl return value.
'''
class PrepInjectWatch():
    def __init__(self, top, cpu, cell_name, mem_utils, dataWatch, kbuffer, lgr):
        self.cpu = cpu
        self.cell_name = cell_name
        self.top = top
        self.dataWatch = dataWatch
        self.lgr = lgr
        self.mem_utils = mem_utils
        self.kbuffer = kbuffer
        self.snap_name = None
        self.len_buf = None
        self.fd = None
        self.call_ip = None
        self.ret_ip = None
        self.ioctl_mark = None
        self.read_mark = None
        self.k_start_ptr = None
        self.k_end_ptr = None
        if cpu.architecture == 'arm':
            self.decode = decodeArm
            self.lgr.debug('setup using arm decoder')
        else:
            self.decode = decode
        if self.kbuffer is not None:
            self.lgr.debug('PrepInjectWatch got kbuffer')
        else:
            self.lgr.debug('PrepInjectWatch NO kbuffer')


    def doInject(self, snap_name, watch_mark):
        ''' Assume the watch mark follows an ioctl 
            that preceeds the read.  We will snapshot 
            prior to the ioctl and record the address of the kernel buffer.'''
        self.top.removeDebugBreaks(keep_watching=False, keep_coverage=True)
        self.snap_name = snap_name
        self.dataWatch.goToMark(watch_mark)
        mark = self.dataWatch.getMarkFromIndex(watch_mark)

        #if type(mark.mark) is watchMarks.CallMark:
        if isinstance(mark.mark, watchMarks.CallMark):
            self.lgr.debug('doInject is call mark')
            if 'ioctl' in mark.mark.getMsg():
                self.len_buf = mark.mark.recv_addr
                self.lgr.debug('is ioctl len_buf is 0x%x' % self.len_buf)
                self.ioctl_mark = watch_mark
                self.read_mark = watch_mark+1           
 
                ''' Try to reverse and find where kernel keeps count data ''' 
                self.top.revTaintAddr(mark.mark.recv_addr, kernel=True, prev_buffer=True, callback=self.handleDelta)

            else:
                self.lgr.debug('prepInjectWatch watch mark is not an ioctl call.')
                self.read_mark = watch_mark
                self.handleReadBuffer(callback=self.instrumentRead)
        else:
            self.lgr.debug('doInject not a CallMark')
               
    def handleDelta(self, buf_addr_list): 
        ''' Assume backtrace stopped at something like rsb r6, r3, r6 
            and then populated buf_addr_list with addresses that contribute to r3 and r6
        '''
        if len(buf_addr_list) != 2:
            self.lgr.error('prepInjectWatch handleDelta unexpected length of buf_addr_list %d' % len(buf_addr_list))
            return 
        self.k_start_ptr = min(buf_addr_list[0], buf_addr_list[1]) 
        self.k_end_ptr = max(buf_addr_list[0], buf_addr_list[1]) 
        self.handleReadBuffer()

    def instrumentAlone(self, buf_addr_list): 
        self.dataWatch.goToMark(self.ioctl_mark)
        self.top.precall()
        self.lgr.debug("prepInjectWatch should be before call to ioctl");
        if len(buf_addr_list) != 1:
            self.lgr.error('prepInjectWatch instrumentAlone unexpected length of buf_addr_list %d' % len(buf_addr_list))
            return 
        buf_addr = buf_addr_list[0]
        self.pickleit(buf_addr)

    def instrumentIO(self, buf_addr_list):
        self.lgr.debug('prepInjectWatch in instrument IO buf_addr_list len is %d' % len(buf_addr_list));
        SIM_run_alone(self.instrumentAlone, buf_addr_list)

    def instrumentRead(self, buf_addr_list):
        self.lgr.debug('prepInjectWatch instrumentRead  buf_addr_list len is %d' % len(buf_addr_list));
        self.dataWatch.goToMark(self.read_mark)
        self.top.precall()
        if len(buf_addr_list) > 1:
            ''' TBD NOT USED '''
            ''' assume x86 dual rep movs...  will be 2 sets of esi, edi '''
            ''' where we found the first byte of the application buffer '''
            app_esi = buf_addr_list[0]
            ''' start of kernel buffer copy '''
            k_esi = buf_addr_list[2]
            ''' destination of kernel buffer copy, will preceed app_esi by some number of bytes.  IP stuff? '''
            k_edi = buf_addr_list[3]
            ''' offset into the kernel buffer where we think data begins '''
            delta = app_esi - k_edi
            ''' address within that kernel buffer '''
            buf_addr = k_esi + delta
            self.lgr.debug('instrumentRead x86 movsb dance, think buf_addr is 0x%x' % buf_addr)
        else:
            buf_addr = buf_addr_list[0]
        self.pickleit(buf_addr)

    def handleReadBuffer(self, callback=None):
        if callback is None:
            callback = self.instrumentIO
        # go to return from a read of interest.
        self.dataWatch.goToMark(self.read_mark)
        mark = self.dataWatch.getMarkFromIndex(self.read_mark)
        self.lgr.debug('prepInjectWatch handleReadBuffer got mark %s' % mark.mark.getMsg())

        ''' go forward one to user space and record the return IP '''
        SIM_run_command('pselect %s' % self.cpu.name)
        SIM_run_command('si')
        self.ret_ip = self.top.getEIP(self.cpu)
        ''' now record the call '''
        frame, cycle = self.top.getPreviousEnterCycle()
        frame_s = 'param1:0x%x param2:0x%x param3:0x%x param4:0x%x param5:0x%x param6:0x%x ' % (frame['param1'], 
            frame['param2'], frame['param3'], frame['param4'], frame['param5'], frame['param6'])
        self.lgr.debug('prepInjectWatch handleReadBuffer got recent cycle 0x%x frame %s' % (cycle, frame_s))
        previous = cycle - 1
        if not resimUtils.skipToTest(self.cpu, previous, self.lgr):
            return
        self.call_ip = self.top.getEIP(self.cpu)
        self.lgr.debug('prepInjectWatch handleReadbuffer got call_ip 0x%x  ret_ip 0x%x' % (self.call_ip, self.ret_ip))

        self.dataWatch.goToMark(self.read_mark)
        if isinstance(mark.mark, watchMarks.CallMark):
            self.lgr.debug('prepInjectWatch 2nd is call mark')
            if 'read' in mark.mark.getMsg() or 'recv' in mark.mark.getMsg():
                self.lgr.debug('is read, jump to prior to the call')
                self.fd = mark.mark.fd
                buf_addr = mark.mark.recv_addr
                self.top.revTaintAddr(buf_addr, kernel=True, prev_buffer=True, callback=callback)
            else:
                self.lgr.debug('prepInjectWatch handleReadBuffer read mark does not look like a read mark: %s' % mark.mark.getMsg())
        else:
            self.lgr.debug('prepInjectWatch handleReadBuffer read mark is not a callMark')

    def pickleit(self, buf_addr):
        self.lgr.debug('prepInjectWatch  pickleit, begin')
        self.top.writeConfig(self.snap_name)
        pickDict = {}
        pickDict['addr'] = buf_addr
        pickDict['call_ip'] = self.call_ip
        pickDict['return_ip'] = self.ret_ip
        pickDict['len_buf'] = self.len_buf
        pickDict['fd'] = self.fd
        ''' POOR names, we don't know which one is the start until we read the values from these addresses '''
        pickDict['k_start_ptr'] = self.k_start_ptr
        pickDict['k_end_ptr'] = self.k_end_ptr
        if self.kbuffer is not None:
            self.lgr.debug('prepInjectWatch pickleit saving kbufs')
            ''' TBD extend to dict to also track cycles so we can inject to middle of a stream, e.g., third read '''
            kbufs = self.kbuffer.getKbuffers()
            pickDict['k_bufs'] = kbufs
            pickDict['k_buf_len'] = self.kbuffer.getBufLength()

        afl_file = os.path.join('./', self.snap_name, self.cell_name, 'afl.pickle')
        pickle.dump( pickDict, open( afl_file, "wb") ) 
        ''' Otherwise console has no indication of when done. '''
        print('Configuration file saved, ok to quit.')
        self.top.quit()
