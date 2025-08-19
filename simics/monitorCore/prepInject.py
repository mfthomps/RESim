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
import os
import pickle
import stopFunction
import resimUtils
import memUtils
import taskUtils
import syscall
import net
from simics import *
'''
Run to an input on the given FD and then save state information in the given snap_name.
State information includes instruction address of the syscall and the return address,
along with the address of the read buffer.
'''
class PrepInject():
    def __init__(self, top, cpu, cell_name, fd, snap_name, count, mem_utils, lgr, commence=None):
        self.cpu = cpu
        self.cell_name = cell_name
        self.fd = fd
        self.top = top
        self.count = count
        self.lgr = lgr
        self.mem_utils = mem_utils
        self.snap_name = snap_name
        self.call_ip = None
        self.return_ip = None
        self.select_call_ip = None
        self.select_return_ip = None
        self.new_origin = None
        self.exit_info = None
        self.ret_cycle = None
        # for windows 
        self.addr_of_count = None

        self.commence = commence


        ''' NOTHING below here '''
        self.prepInject()


    def prepInject(self, dumb=None, ignore_waiting=False):
        ''' Use runToInput/runToIO to find location of desired input call.  Set callback to instrument the call and return '''
        self.lgr.debug('prepInject snap %s FD: %d (0x%x) commence: %s' % (self.snap_name, self.fd, self.fd, self.commence))
        ''' passing "cb_param" causes stop function to use parameter passed by the stop hap, which should be the callname '''
        self.top.stopWatchPageFaults()
        f1 = stopFunction.StopFunction(self.instrumentIO, ['cb_param'], nest=False)
        flist = [f1]
        if self.top.isWindows():
            self.top.runToIO(self.fd, flist_in=flist, count=self.count, sub_match=self.commence, just_input=True)
        else:
            self.top.runToInput(self.fd, flist_in=flist, count=self.count, ignore_waiting=ignore_waiting, sub_match=self.commence)

    def instrumentSelect(self, dumb):
        #self.top.removeDebugBreaks(keep_watching=False, keep_coverage=True)
        self.top.stopTracking(keep_coverage=True)
        ''' go forward one to user space and record the return IP '''
        SIM_run_command('pselect %s' % self.cpu.name)
        SIM_run_command('si')
        self.select_return_ip = self.top.getEIP(self.cpu)
        self.ret_cycle = self.cpu.cycles
        tid = self.top.getTID()
        self.lgr.debug('prepInject instrumentSelect stepped to return IP: 0x%x tid:%s cycle is 0x%x' % (self.select_return_ip, tid, self.cpu.cycles))
        ''' return to the call to record that IP '''
        frame, cycle = self.top.getRecentEnterCycle()
        origin = self.top.getFirstCycle()
        self.lgr.debug('prepInject instrumentSelect origin 0x%x recent call cycle 0x%x' % (origin, cycle))
        if cycle <= origin:
            self.lgr.debug('prepInject instrumentSelect Entry into kernel is prior to first cycle, cannot record select_ip')
        else:
            previous = cycle - 1
            self.top.skipToCycle(previous, cpu=self.cpu, disable=True)
            self.select_call_ip = self.top.getEIP(self.cpu)
            self.lgr.debug('instrumentSelect skipped to call: 0x%x tid:%s cycle is 0x%x' % (self.select_call_ip, tid, self.cpu.cycles))
            ''' now back to return '''
            self.top.skipToCycle(self.ret_cycle, cpu=self.cpu, disable=True)
        self.top.restoreDebugBreaks()
        self.prepInject(ignore_waiting=True)

    def finishNoCall(self, read_original=True):
        # TBD point of runToIO check?
        #syscall = self.top.getSyscall(self.cell_name, 'runToIO')
        orig_buffer = None
        if True or syscall is not None:
            if read_original:
                length = self.getLength()
                ''' TBD if this falls on a page boundary, cannot get all original bytes?  be sure to run the service first!'''
                orig_buffer = self.mem_utils.readBytes(self.cpu, self.exit_info.retval_addr, length)
                if orig_buffer is not None:
                    self.lgr.debug('prepInject instrumentAlone got orig buffer from phys memory len %d syscall len was %d' % (len(orig_buffer), length))
                else:
                    self.lgr.error('prepInject instrumentAlone failed to get orig buffer from syscall') 
                self.top.skipToCycle(self.ret_cycle, cpu=self.cpu, disable=True)
            self.pickleit(self.snap_name, self.exit_info, orig_buffer)
        #else:
        #    self.lgr.error('prepInject finishNoCall falled to get syscall ?')

    def tidScheduled(self, dumb=None):
        self.lgr.debug('prepInject tidScheduled')
        pinfo = self.top.pageInfo(self.exit_info.retval_addr, quiet=True)
        self.lgr.debug('%s' % pinfo.valueString())
        self.top.stopAndGo(self.finishNoCall)

    def getLength(self):
        if self.exit_info.sock_struct is not None:
            length = self.exit_info.sock_struct.length
            self.lgr.debug('prepInject getLength length from sock_struct is %d' % length)
            if length == 0:
                length = self.exit_info.count
                self.lgr.debug('prepInject getLength length from sock_struct was zero, use count %d ***TBD FIX THIS' % length)
        else:
            length = self.exit_info.count
            self.lgr.debug('prepInject getLength length from count is %d' % length)
            if self.top.isWindows():
                #if self.exit_info.did_delay:
                #    self.addr_of_count = self.exit_info.delay_count_addr
                #else:
                #    self.addr_of_count = self.exit_info.count_addr
                self.addr_of_count = self.exit_info.delay_count_addr
                self.lgr.debug('prepInject getLength windows, address of count 0x%x' % self.addr_of_count)
        return length

    def instrumentAlone(self, dumb): 
        #self.top.removeDebugBreaks(keep_watching=True, keep_coverage=True)
        self.top.stopTracking(keep_watching=True, keep_coverage=True)
        current_ip = self.top.getEIP(self.cpu)
        tid = self.top.getTID()
        self.lgr.debug('prepInject instrumentAlone tid %s ip 0x%x' % (tid, current_ip))
        if self.mem_utils.isKernel(current_ip): 
            ''' go forward one to user space and record the return IP '''
            SIM_run_command('pselect %s' % self.cpu.name)
            SIM_run_command('si')
            self.return_ip = self.top.getEIP(self.cpu)
            self.lgr.debug('instrument snap_name %s stepped to return IP: 0x%x entry ip: 0x%x tid:%s cycle is 0x%x' % (self.snap_name, self.return_ip, 
                  current_ip, tid, self.cpu.cycles))
        else:
            self.return_ip = current_ip
            self.lgr.debug('instrument snap_name %s landed in user space. return IP: 0x%x entry ip: 0x%x tid:%s cycle is 0x%x' % (self.snap_name, self.return_ip, 
                  current_ip, tid, self.cpu.cycles))
        self.ret_cycle = self.cpu.cycles

        ''' Find the exit info from the system call that did the read.'''
        self.exit_info = self.top.getMatchingExitInfo()

        tid = self.top.getTID()
        length = self.getLength()
        ''' Save the buffer read at point of prep inject, e.g., for use as a seed'''

        if self.top.isWindows():
            ret_count = self.mem_utils.readWord(self.cpu, self.addr_of_count)
            if ret_count > length:
               self.lgr.debug('prepInject instrument count value bogus set to length %d' % length)
               ret_count = length 
            self.lgr.debug('prepInject instrument Last buffer addr_of_count 0x%x ret_count %d' % (self.addr_of_count, ret_count))
        else:
            ret_count = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')

        the_buffer = self.mem_utils.readBytes(self.cpu, self.exit_info.retval_addr, ret_count) 
        with open('logs/orig_buffer.io', 'bw') as fh:
            fh.write(the_buffer)
        self.lgr.debug('prepInject instrument Last buffer of %d bytes written to logs/orig_buffer.io' % ret_count)
        print('Last buffer of %d bytes written to logs/orig_buffer.io' % ret_count)

        frame, cycle = self.top.getRecentEnterCycle()
        origin = self.top.getFirstCycle()
        call = self.top.syscallName(frame['syscall_num'])
        self.lgr.debug('prepInject instrumentAlone origin 0x%x recent call cycle 0x%x tid:%s call %s' % (origin, cycle, tid, call))
        if cycle <= origin:
            self.lgr.debug('prepInject instrumentAlone Entry into kernel is prior to first cycle, cannot record call_ip')
            if self.top.didMagicOrigin():
                self.lgr.debug('prepInject instrumentAlone go to origin')
                self.top.goToOrigin()
                self.lgr.debug('prepInject instrumentAlone back from go to origin, do toTid')
                self.top.toTid(tid, callback = self.tidScheduled)
            else:
                print('Warning: No magic instruction 99 detected, and thus original buffer data will not be restored.')
                print('Content of the buffer is corrupted by the data sent to the target for prep_inject.')
                self.finishNoCall(read_original=False)          
        else: 
            if self.exit_info.retval_addr is None:
                self.lgr.error('prepInject instrumentAlone, retval_addr is None')
                return
            orig_buffer = None
            ''' return to the call to record that IP and original data in the buffer.  That is in case we inject less than the most recent read,
                the remaining data will not reflect what it would have been.'''
            previous = cycle - 1
            self.lgr.debug('prepInject instrument try to skip to previous cycle 0x%x' % previous)

            if self.top.skipToCycle(previous, cpu=self.cpu, disable=True):
                self.call_ip = self.top.getEIP(self.cpu)
                ''' TBD generalize for use with recvmsg msghdr multiple buffers'''
                orig_buffer = self.mem_utils.readBytes(self.cpu, self.exit_info.retval_addr, length) 
                self.lgr.debug('instrument  skipped to call IP: 0x%x tid:%s callnum: %d cycle is 0x%x len of orig_buffer %d' % (self.call_ip, tid, frame['syscall_num'], self.cpu.cycles, len(orig_buffer)))
            else:
                self.lgr.error('prepInject instrument failed skip to syscall')
            ''' skip back to return so the snapshot is ready to inject input '''
            self.lgr.debug('prepInjectInstrument skip back to ret_cycle 0x%x' % self.ret_cycle)
            self.top.skipToCycle(self.ret_cycle, cpu=self.cpu, disable=True)
            current_ip = self.top.getEIP(self.cpu)
            self.lgr.debug('instrument skipped to ret cycle 0x%x eip now 0x%x' % (self.ret_cycle, current_ip))
            self.pickleit(self.snap_name, self.exit_info, orig_buffer)

    def instrumentIO(self, callname):
        self.lgr.debug("prepInject in instrument IO, callname is %s" % callname);
        if self.top.isWindows():
            self.lgr.debug("prepInject in instrument IO")
            if callname in ['GET_PEER_NAME']:
                SIM_run_alone(self.prepInject, None)
            else:
                SIM_run_alone(self.instrumentAlone, None)
        elif callname.startswith('re') or callname == 'socketcall':
            SIM_run_alone(self.instrumentAlone, None)
        elif 'select' in callname:
            self.lgr.debug('prepInject instrumentIO call to instrumentSelect')
            SIM_run_alone(self.instrumentSelect, None)
        else:
            self.lgr.error('preInject instrumentIO could not handle callname %s' % callname)

    def pickleit(self, name, exit_info, orig_buffer):
        self.lgr.debug('prepInject pickleit, begin')
        self.top.writeConfig(name)
        pickDict = {}
        pickDict['call_ip'] = self.call_ip
        pickDict['return_ip'] = self.return_ip
        pickDict['select_call_ip'] = self.select_call_ip
        pickDict['select_return_ip'] = self.select_return_ip
        pickDict['addr'] = exit_info.retval_addr
        pickDict['fd'] = exit_info.old_fd
        pickDict['callnum'] = exit_info.callnum
        pickDict['socket_callname'] = exit_info.socket_callname
        pickDict['size'] = self.getLength()
        self.lgr.debug('prepInject pickleit save addr 0x%x size %d' % (pickDict['addr'], pickDict['size']))
        ''' Otherwise console has no indiation of when done. '''

        if self.top.isWindows():
            if exit_info.fname_addr is not None:
                pickDict['addr_addr'] = exit_info.sock_addr
                pickDict['addr_size'] = 8
                self.lgr.debug('prepInject pickleit addr_addr is 0x%x' % exit_info.sock_addr)
        elif exit_info.src_addr is not None:
            count = self.mem_utils.readWord32(self.cpu, exit_info.src_addr_len)
            pickDict['addr_addr'] = exit_info.src_addr_len
            pickDict['addr_size'] = count

        pickDict['orig_buffer'] = orig_buffer
        if self.top.isWindows():
            pickDict['addr_of_count'] = self.addr_of_count
        afl_file = os.path.join('./', name, self.cell_name, 'afl.pickle')
        pickle.dump( pickDict, open( afl_file, "wb") ) 
        if self.call_ip is not None:
            self.lgr.debug('call_ip 0x%x return_ip 0x%x' % (self.call_ip, self.return_ip))
        else:
            self.lgr.debug('call_ip NONE return_ip 0x%x' % (self.return_ip))
        print('Configuration file saved, ok to quit.')
