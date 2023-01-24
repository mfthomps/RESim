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
    def __init__(self, top, cpu, cell_name, fd, snap_name, count, mem_utils, lgr):
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


        ''' NOTHING below here '''
        self.prepInject()


    def prepInject(self):
        ''' Use runToInput to find location of desired input call.  Set callback to instrument the call and return '''
        self.lgr.debug('prepInject snap %s' % self.snap_name)
        ''' passing "cb_param" causes stop function to use parameter passed by the stop hap, which should be the callname '''
        f1 = stopFunction.StopFunction(self.instrumentIO, ['cb_param'], nest=False)
        flist = [f1]
        self.top.runToInput(self.fd, flist_in=flist, count=self.count)

    def instrumentSelect(self, dumb):
        self.top.removeDebugBreaks(keep_watching=False, keep_coverage=True)
        ''' go forward one to user space and record the return IP '''
        SIM_run_command('pselect %s' % self.cpu.name)
        SIM_run_command('si')
        self.select_return_ip = self.top.getEIP(self.cpu)
        self.ret_cycle = self.cpu.cycles
        pid = self.top.getPID()
        self.lgr.debug('instrumentSelect stepped to return IP: 0x%x pid:%d cycle is 0x%x' % (self.select_return_ip, pid, self.cpu.cycles))
        ''' return to the call to record that IP '''
        frame, cycle = self.top.getRecentEnterCycle()
        origin = self.top.getFirstCycle()
        self.lgr.debug('instrument origin 0x%x recent call cycle 0x%x' % (origin, cycle))
        if cycle <= origin:
            self.lgr.debug('prepInject instrumentSelect Entry into kernel is prior to first cycle, cannot record select_ip')
        else:
            previous = cycle - 1
            resimUtils.skipToTest(self.cpu, previous, self.lgr)
            self.select_call_ip = self.top.getEIP(self.cpu)
            self.lgr.debug('instrumentSelect skipped to call: 0x%x pid:%d cycle is 0x%x' % (self.select_call_ip, pid, self.cpu.cycles))
            ''' now back to return '''
            resimUtils.skipToTest(self.cpu, self.ret_cycle, self.lgr)
        self.top.restoreDebugBreaks()
        self.prepInject()

    def finishNoCall(self, read_original=True):
        syscall = self.top.getSyscall(self.cell_name, 'runToInput')
        if syscall is not None:
            if read_original:
                if self.exit_info.sock_struct is not None:
                    length = self.exit_info.sock_struct.length
                else:
                    length = self.exit_info.count
                ''' TBD if this falls on a page boundary, cannot get all original bytes?  be sure to run the service first!'''
                orig_buffer = self.mem_utils.readBytes(self.cpu, self.exit_info.retval_addr, length)
                #orig_buffer, dumb = self.mem_utils.getBytes(self.cpu, length, retval_addr_phys, phys_in=True)
                if orig_buffer is not None:
                    self.lgr.debug('prepInject instrumentAlone got orig buffer from phys memory len %d syscall len was %d' % (len(orig_buffer), length))
                else:
                    self.lgr.error('prepInject instrumentAlone failed to get orig buffer from syscall') 
                resimUtils.skipToTest(self.cpu, self.ret_cycle, self.lgr)
            self.pickleit(self.snap_name, self.exit_info, orig_buffer)
        else:
            self.lgr.error('prepInject finishNoCall falled to get syscall ?')

    def pidScheduled(self, dumb):
        self.lgr.debug('prepInject pidScheduled')
        pinfo = self.top.pageInfo(self.exit_info.retval_addr, quiet=True)
        self.lgr.debug('%s' % pinfo.valueString())
        self.top.stopAndGo(self.finishNoCall)

    def instrumentAlone(self, dumb): 
        self.top.removeDebugBreaks(keep_watching=True, keep_coverage=True)
        ''' go forward one to user space and record the return IP '''
        SIM_run_command('pselect %s' % self.cpu.name)
        SIM_run_command('si')
        self.return_ip = self.top.getEIP(self.cpu)
        self.ret_cycle = self.cpu.cycles
        pid = self.top.getPID()
        self.lgr.debug('instrument snap_name %s stepped to return IP: 0x%x pid:%d cycle is 0x%x' % (self.snap_name, self.return_ip, pid, self.cpu.cycles))


        self.exit_info = self.top.getMatchingExitInfo()

        pid = self.top.getPID()
        if self.exit_info.sock_struct is not None:
            length = self.exit_info.sock_struct.length
        else:
            length = self.exit_info.count

        frame, cycle = self.top.getRecentEnterCycle()
        origin = self.top.getFirstCycle()
        self.lgr.debug('instrument origin 0x%x recent call cycle 0x%x' % (origin, cycle))
        if cycle <= origin:
            self.lgr.debug('Entry into kernel is prior to first cycle, cannot record call_ip')
            if self.top.didMagicOrigin():
                self.top.goToOrigin()
                self.top.toPid(pid, callback = self.pidScheduled)
            else:
                print('Warning: No magic instruction 99 detected, and thus original buffer data will not be restored.')
                print('Content of the buffer is corrupted by the data sent to the target for prep_inject.')
                self.finishNoCall(read_original=False)          
        else: 
            ''' return to the call to record that IP and original data in the buffer'''
            previous = cycle - 1
            resimUtils.skipToTest(self.cpu, previous, self.lgr)
            self.call_ip = self.top.getEIP(self.cpu)
            if self.exit_info.retval_addr is None:
                self.lgr.error('instrumentAlone, retval_addr is None')
                return

            orig_buffer = self.mem_utils.readBytes(self.cpu, self.exit_info.retval_addr, length) 
            self.lgr.debug('instrument  skipped to call IP: 0x%x pid:%d callnum: %d cycle is 0x%x len of orig_buffer %d' % (self.call_ip, pid, frame['syscall_num'], self.cpu.cycles, len(orig_buffer)))
            ''' skip back to return so the snapshot is ready to inject input '''
            resimUtils.skipToTest(self.cpu, self.ret_cycle, self.lgr)
            self.pickleit(self.snap_name, self.exit_info, orig_buffer)

    def instrumentIO(self, callname):
        self.lgr.debug("prepInject in instrument IO, callname is %s" % callname);
        if callname.startswith('re') or callname == 'socketcall':
            SIM_run_alone(self.instrumentAlone, None)
        elif 'select' in callname:
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
        if exit_info.sock_struct is not None:
            pickDict['size'] = exit_info.sock_struct.length
        else:
            pickDict['size'] = exit_info.count
        self.lgr.debug('prepInject pickleit save addr 0x%x size %d' % (pickDict['addr'], pickDict['size']))
        ''' Otherwise console has no indiation of when done. '''

        if exit_info.fname_addr is not None:
            count = self.mem_utils.readWord32(self.cpu, exit_info.count)
            pickDict['addr_addr'] = exit_info.fname_addr
            pickDict['addr_size'] = count

        pickDict['orig_buffer'] = orig_buffer
        afl_file = os.path.join('./', name, self.cell_name, 'afl.pickle')
        pickle.dump( pickDict, open( afl_file, "wb") ) 
        if self.call_ip is not None:
            self.lgr.debug('call_ip 0x%x return_ip 0x%x' % (self.call_ip, self.return_ip))
        else:
            self.lgr.debug('call_ip NONE return_ip 0x%x' % (self.return_ip))
        print('Configuration file saved, ok to quit.')
