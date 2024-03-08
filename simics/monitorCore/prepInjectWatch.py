import os
import pickle
import stopFunction
import watchMarks
from simics import *
import decode
import decodeArm
import resimUtils
'''
Create a snapshot from a given watch mark index value, 
which may be a read or an ioctl.  The snapshot will preceed the call, and
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
        self.orig_buffer = None
        self.user_addr = None
        if cpu.architecture == 'arm':
            self.decode = decodeArm
            self.lgr.debug('setup using arm decoder')
        else:
            self.decode = decode
        if self.kbuffer is not None:
            self.lgr.debug('PrepInjectWatch got kbuffer')
        else:
            self.lgr.debug('PrepInjectWatch NO kbuffer')

        self.read_count_addr = None

    def doInject(self, snap_name, watch_mark):
        ''' Find kernel buffer used for read/recv calls '''
        self.lgr.debug('prepInjectWatch doInject snap %s mark %d' % (snap_name, watch_mark))
        self.top.removeDebugBreaks(keep_watching=False, keep_coverage=True)
        self.snap_name = snap_name
        self.dataWatch.stopWatch(immediate=True)
        self.dataWatch.goToMark(watch_mark)
        mark = self.dataWatch.getMarkFromIndex(watch_mark)

        if self.kbuffer is not None:
            k_buf_len = self.kbuffer.getBufLength()
            if k_buf_len is None or k_buf_len == 0:
                self.lgr.error('prepInjectWatch kbuffer is empty.  Exit')
                self.top.quit()
            
            ''' Watch mark should leave us after the return '''
            self.ret_ip = self.top.getEIP(self.cpu)
           
            ''' Jump to prior to call to record the call address ''' 
            self.top.precall()
            self.call_ip = self.top.getEIP(self.cpu)

            ''' Now jump to just before kernel starting moving data from kernel buffer to application buffer '''
            kcycle = self.kbuffer.getKernelCycleOfWrite() 
            if not resimUtils.skipToTest(self.cpu, kcycle, self.lgr):
                self.lgr.error('prepInjectWatch doInject failed skipping to kcyle 0x%x' % kcycle)
                return
            self.lgr.debug('prepInjectWatch doInject jumped to kcycle just before buffer copy 0x%x' % kcycle)
            kbufs = self.kbuffer.getKbuffers()
            self.fd = mark.mark.fd

            ''' Get the read count address, e.g., if windows.  TBD linux?'''
            next_mark = watch_mark+1
            read_count_addr_maybe = self.dataWatch.getMarkFromIndex(next_mark)
            if read_count_addr_maybe is not None:
                self.lgr.debug('prepInjectWatch doInject read_count_addr_maybe %s' % read_count_addr_maybe.mark.getMsg())
                if read_count_addr_maybe is not None and read_count_addr_maybe.mark.getMsg().startswith('read count'):
                   self.read_count_addr = read_count_addr_maybe.mark.recv_addr 
                   self.lgr.debug('prepInjectWatch doInject read_count_addr found 0x%x' % self.read_count_addr)
            
            self.pickleit(kbufs[0])  
        else:
            self.lgr.error('prepInjectWatch called with no kbuffer.  Exit')
            self.top.quit()
               

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


    def pickleit(self, buf_addr):
        self.lgr.debug('prepInjectWatch  pickleit, begin')
        self.top.writeConfig(self.snap_name)
        pickDict = {}
        pickDict['addr'] = buf_addr
        pickDict['call_ip'] = self.call_ip
        pickDict['return_ip'] = self.ret_ip
        pickDict['len_buf'] = self.len_buf
        pickDict['fd'] = self.fd
        self.lgr.debug('prepInjectWatch pickleit fd %s' % self.fd)
        if self.fd is None:
            self.lgr.error('prepInjectWatch pickleit NO FD is set.  Was the watch mark a read/recv?')
            return
        ''' POOR names, we don't know which one is the start until we read the values from these addresses '''
        pickDict['k_start_ptr'] = self.k_start_ptr
        pickDict['k_end_ptr'] = self.k_end_ptr
        if self.kbuffer is not None:
            ''' TBD extend to dict to also track cycles so we can inject to middle of a stream, e.g., third read '''
            kbufs = self.kbuffer.getKbuffers()
            pickDict['k_bufs'] = kbufs
            k_buf_len = self.kbuffer.getBufLength()
            pickDict['k_buf_len'] = k_buf_len
            pickDict['user_addr'] = self.kbuffer.getUserAddr()
            pickDict['user_count'] = self.kbuffer.getUserCount()
            orig_buf = self.kbuffer.getOrigBuf()
            pickDict['orig_buffer'] = orig_buf
            if orig_buf is not None:
                self.lgr.debug('prepInjectWatch pickleit saving %d kbufs of len %d.  Orig buffer len %d' % (len(kbufs), k_buf_len, len(orig_buf)))
            else:
                self.lgr.debug('prepInjectWatch pickleit saving %d kbufs of len %d.  ' % (len(kbufs), k_buf_len))
        if self.top.isWindows():
            pickDict['addr_of_count'] = self.read_count_addr

        afl_file = os.path.join('./', self.snap_name, self.cell_name, 'afl.pickle')
        pickle.dump( pickDict, open( afl_file, "wb") ) 
        ''' Otherwise console has no indication of when done. '''
        print('Configuration file saved, ok to quit.')
        self.top.quit()
