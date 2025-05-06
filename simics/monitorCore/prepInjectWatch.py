import os
import pickle
import stopFunction
import watchMarks
from simics import *
import decode
import decodeArm
import resimUtils
import kbuffer
'''
Create a snapshot from a given watch mark index value, 
which may be a read or an ioctl.  The snapshot will preceed the call, and
will include the address of the kernel buffer, and the kernel pointers
used ot calculate the ioctl return value.
'''
class PrepInjectWatch():
    def __init__(self, top, cpu, cell_name, mem_utils, dataWatch, context_manager, kbuffer, lgr):
        self.cpu = cpu
        self.cell_name = cell_name
        self.top = top
        self.dataWatch = dataWatch
        self.context_manager = context_manager
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
        self.stop_hap = None

    def doInject(self, snap_name, watch_mark):
        ''' Find kernel buffer used for read/recv calls '''
        self.lgr.debug('prepInjectWatch doInject snap %s mark %d' % (snap_name, watch_mark))
        self.top.removeDebugBreaks(keep_watching=False, keep_coverage=True)
        self.snap_name = snap_name
        self.dataWatch.stopWatch(immediate=True)
        is_ioctl = False
        mark = None
        if watch_mark != 0:
            self.dataWatch.goToMark(watch_mark)
            mark = self.dataWatch.getMarkFromIndex(watch_mark)
            if isinstance(mark.mark, watchMarks.CallMark):
                msg = mark.mark.getMsg()
                self.lgr.debug('prepInjectWatch given mark is %s' % msg)
                if 'ioctl' in msg:
                    is_ioctl = True
            else:
                self.lgr.error('prepInjectWatch given mark not a call mark, is %s' % mark.mark.getMsg())
                self.top.quit()
        if self.kbuffer is None:
            self.kbuffer = kbuffer.Kbuffer(self.top, self.cpu, self.context_manager, self.mem_utils, self.dataWatch, self.lgr, stop_when_done=True)
            next_call = self.dataWatch.nextCallMark()
            if next_call is None:
                self.lgr.error('prepInjectWatch doInject lacks kbuffer and there are no call marks.')
                return
            call_mark = self.dataWatch.getMarkFromIndex(next_call)
            self.dataWatch.goToMark(next_call)
            frame, recent_entry = self.top.getPreviousEnterCycle()
            if not self.top.skipToCycle(recent_entry, self.cpu, disable=True):
                self.lgr.error('prepInjectWatch doInject failed skipping to recent_entry 0x%x' % recent_entry)
                self.top.quit()
                return
            read_addr = call_mark.mark.recv_addr
            read_count = call_mark.mark.len
            self.kbuffer.read(read_addr, read_count)
            self.lgr.debug('prepInjectWatch did kbuffer read for addr 0x%x count 0x%x' % (read_addr, read_count))
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap, watch_mark)
            SIM_continue(0)
            return

        if self.kbuffer is not None:
            k_buf_len_list = self.kbuffer.getBufLength()
            self.lgr.debug('prepInjectWatch kbuffer exists, first buf len reported as 0x%x' %  k_buf_len_list[0])
            if len(k_buf_len_list) == 0 or k_buf_len_list[0] == 0:
                self.lgr.error('prepInjectWatch kbuffer is empty.  Exit')
                self.top.quit()
            
            ''' Watch mark should leave us after the return '''
            self.ret_ip = self.top.getEIP(self.cpu)
           
            ''' Jump to prior to call to record the call address ''' 
            cycle_was = self.cpu.cycles
            self.top.precall()
            self.call_ip = self.top.getEIP(self.cpu)

            if not is_ioctl:
                ''' Now jump to just before kernel starting moving data from kernel buffer to application buffer '''
                kcycle = self.kbuffer.getKernelCycleOfWrite() 
                if kcycle != self.cpu.cycles:
                    if not self.top.skipToCycle(kcycle, self.cpu, disable=True):
                        self.lgr.error('prepInjectWatch doInject failed skipping to kcycle 0x%x' % kcycle)
                        #self.top.quit()
                        return
                    self.lgr.debug('prepInjectWatch doInject jumped to kcycle just before buffer copy 0x%x' % kcycle)
                else:
                    self.lgr.debug('prepInjectWatch doInject was already at kcycle just before buffer copy 0x%x' % kcycle)
            else:
                if not self.top.skipToCycle(cycle_was, self.cpu, disable=True):
                    self.lgr.error('prepInjectWatch doInject failed skipping to cycle_was 0x%x' % cycle_was)
                    self.top.quit()
                    return
                self.lgr.debug('prepInjectWatch doInject is ioctl, skipped to return at cycle 0x%x' % self.cpu.cycles)
                self.read_count_addr = mark.mark.recv_addr
                self.lgr.debug('prepInjectWatch doInject read_count_addr found 0x%x' % self.read_count_addr)
            kbufs = self.kbuffer.getKbuffers()
            if mark is not None:
                # TBD will the ever be different?
                self.fd = mark.mark.fd
            else:
                self.fd = self.kbuffer.getFD()

            ''' Get the read count address, e.g., if windows.  TBD linux?'''
            next_mark = watch_mark+1
            read_count_addr_maybe = self.dataWatch.getMarkFromIndex(next_mark)
            if read_count_addr_maybe is not None:
                self.lgr.debug('prepInjectWatch doInject read_count_addr_maybe %s' % read_count_addr_maybe.mark.getMsg())
                if read_count_addr_maybe is not None and read_count_addr_maybe.mark.getMsg().startswith('read count'):
                   self.read_count_addr = read_count_addr_maybe.mark.recv_addr 
                   self.lgr.debug('prepInjectWatch doInject read_count_addr found 0x%x' % self.read_count_addr)
            
            self.pickleit(kbufs[0], is_ioctl)  
        else:
            self.lgr.error('prepInjectWatch called with no kbuffer.  Exit')
            self.top.quit()
               
    '''
    def instrumentAlone(self, buf_addr_list): 
        # TBD remove not used
        self.dataWatch.goToMark(self.ioctl_mark)
        self.top.precall()
        self.lgr.debug("prepInjectWatch should be before call to ioctl");
        if len(buf_addr_list) != 1:
            self.lgr.error('prepInjectWatch instrumentAlone unexpected length of buf_addr_list %d' % len(buf_addr_list))
            return 
        buf_addr = buf_addr_list[0]
        self.pickleit(buf_addr)

    def instrumentIO(self, buf_addr_list):
        # TBD remove not used
        self.lgr.debug('prepInjectWatch in instrument IO buf_addr_list len is %d' % len(buf_addr_list));
        SIM_run_alone(self.instrumentAlone, buf_addr_list)
    '''


    def pickleit(self, buf_addr, is_ioctl):
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
            k_buf_len_list = self.kbuffer.getBufLength()
            pickDict['k_buf_len'] = k_buf_len_list
            pickDict['user_addr'] = self.kbuffer.getUserAddr()
            pickDict['user_count'] = self.kbuffer.getUserCount()
            orig_buf = self.kbuffer.getOrigBuf()
            pickDict['orig_buffer'] = orig_buf
            if orig_buf is not None:
                self.lgr.debug('prepInjectWatch pickleit saving %d kbufs of len list %s.  Orig buffer len %d' % (len(kbufs), str(k_buf_len_list), 
                                len(orig_buf)))
            else:
                self.lgr.debug('prepInjectWatch pickleit saving %d kbufs of len list %s.  ' % (len(kbufs), str(k_buf_len_list)))
            pickDict['tid'] = self.kbuffer.getTID()
        if self.top.isWindows():
            pickDict['addr_of_count'] = self.read_count_addr
        elif is_ioctl:
            pickDict['addr_of_count'] = self.read_count_addr
            self.lgr.debug('prepInjectWatch pickleit saving addr_of_count 0x%x' % self.read_count_addr)

        afl_file = os.path.join('./', self.snap_name, self.cell_name, 'afl.pickle')
        with open( afl_file, "wb") as fh:
            pickle.dump( pickDict, fh)
        ''' Otherwise console has no indication of when done. '''
        print('Configuration file saved, ok to quit.')
        self.top.quit()

    def redoPrep(self, watch_mark):
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
        self.stop_hap = None
        self.lgr.debug('prepInjectWatch redoPrep, now call doInject again')
        self.doInject(self.snap_name, watch_mark)

    def stopHap(self, watch_mark, one, exception, error_string):
        if self.stop_hap is None:
            return
        self.lgr.debug('prepInjectWatch stopHap, must have kernel buffer')
        SIM_run_alone(self.redoPrep, watch_mark) 
