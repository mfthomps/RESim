import os
import pickle
import stopFunction
import watchMarks
from simics import *
import decode
import decodeArm
'''
Create a snapshot from a given watch mark index value, intended to
be an ioctl.  The snapshot will preceed the ioctl call, and
will include the address of the kernel buffer, and the kernel pointers
used ot calculate the ioctl return value.
'''
class PrepInjectWatch():
    def __init__(self, top, cpu, cell_name, mem_utils, dataWatch, lgr):
        self.cpu = cpu
        self.cell_name = cell_name
        self.top = top
        self.dataWatch = dataWatch
        self.lgr = lgr
        self.mem_utils = mem_utils
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


    def doInject(self, snap_name, watch_mark):
        ''' Assume the watch mark follows an ioctl 
            that preceeds the read.  We will snapshot 
            prior to the ioctl and record the address of the kernel buffer.'''
        self.top.removeDebugBreaks(keep_watching=False, keep_coverage=True)
        self.snap_name = snap_name
        self.dataWatch.goToMark(watch_mark)
        mark = self.dataWatch.getMarkFromIndex(watch_mark)
        self.lgr.debug('doInject got mark %s' % mark.mark.getMsg())
        if type(mark.mark) is watchMarks.CallMark:
            self.lgr.debug('doInject is call mark')
            if 'ioctl' in mark.mark.getMsg():
                self.len_buf = mark.mark.recv_addr
                self.lgr.debug('is ioctl len_buf is 0x%x' % self.len_buf)
                self.ioctl_mark = watch_mark
                self.read_mark = watch_mark+1           
 
                ''' Try to reverse and find where kernel keeps count data ''' 
                self.top.revTaintAddr(mark.mark.recv_addr, kernel=True, prev_buffer=True, callback=self.handleDelta)

            else:
                self.lgr.error('prepInjectWatch watch mark is not an ioctl call.')
               
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
         

    def handleReadBuffer(self):
        ''' now assume watch_mark is at return from a read of interest.'''
        self.dataWatch.goToMark(self.read_mark)
        mark = self.dataWatch.getMarkFromIndex(self.read_mark)
        self.lgr.debug('doInject got mark %s' % mark.mark.getMsg())
        if type(mark.mark) is watchMarks.CallMark:
            self.lgr.debug('doInject 2nd is call mark')
            if 'read' in mark.mark.getMsg():
                self.lgr.debug('is read, jump to prior to the call')
                self.fd = mark.mark.fd
                buf_addr = mark.mark.recv_addr
                self.top.revTaintAddr(buf_addr, kernel=True, prev_buffer=True, callback=self.instrumentIO)

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
        afl_file = os.path.join('./', self.snap_name, self.cell_name, 'afl.pickle')
        pickle.dump( pickDict, open( afl_file, "wb") ) 
        ''' Otherwise console has no indiation of when done. '''
        print('Configuration file saved, ok to quit.')
