import os
import pickle
import stopFunction
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
        self.prepInject()

    def prepInject(self):
        ''' Use runToInput to find location of desired input call.  Set callback to instrument the call and return '''
        self.lgr.debug('afl prepInject snap %s' % self.snap_name)
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
        ret_cycle = self.cpu.cycles
        pid = self.top.getPID()
        self.lgr.debug('instrumentSelect stepped to return IP: 0x%x pid:%d cycle is 0x%x' % (self.select_return_ip, pid, self.cpu.cycles))
        ''' return to the call to record that IP '''
        frame, cycle = self.top.getRecentEnterCycle()
        previous = cycle - 1
        SIM_run_command('skip-to cycle=%d' % previous)
        self.select_call_ip = self.top.getEIP(self.cpu)
        self.lgr.debug('instrumentSelect skipped to call: 0x%x pid:%d cycle is 0x%x' % (self.select_call_ip, pid, self.cpu.cycles))
        ''' now back to return '''
        SIM_run_command('skip-to cycle=%d' % ret_cycle)
        self.top.restoreDebugBreaks()
        self.prepInject()

    def instrumentAlone(self, dumb): 
        self.top.removeDebugBreaks(keep_watching=True, keep_coverage=True)
        ''' go forward one to user space and record the return IP '''
        SIM_run_command('pselect %s' % self.cpu.name)
        SIM_run_command('si')
        self.return_ip = self.top.getEIP(self.cpu)
        ret_cycle = self.cpu.cycles
        pid = self.top.getPID()
        self.lgr.debug('instrument snap_name %s stepped to return IP: 0x%x pid:%d cycle is 0x%x' % (self.snap_name, self.return_ip, pid, self.cpu.cycles))
        ''' return to the call to record that IP and original data in the buffer'''
        exit_info = self.top.getMatchingExitInfo()
        frame, cycle = self.top.getRecentEnterCycle()
        origin = self.top.getFirstCycle()
        self.lgr.debug('instrument origin 0x%x recent call cycle 0x%x' % (origin, cycle))
        if cycle <= origin:
            self.lgr.debug('Entry into kernel is prior to first cycle, cannot record call_ip')
        else: 
            previous = cycle - 1
            SIM_run_command('skip-to cycle=%d' % previous)
            self.call_ip = self.top.getEIP(self.cpu)
            self.lgr.debug('instrument  skipped to call IP: 0x%x pid:%d callnum: %d cycle is 0x%x' % (self.call_ip, pid, frame['syscall_num'], self.cpu.cycles))
            ''' skip back to return so the snapshot is ready to inject input '''
            SIM_run_command('skip-to cycle=%d' % ret_cycle)
        pid = self.top.getPID()
        if exit_info.sock_struct is not None:
            length = exit_info.sock_struct.length
        else:
            length = exit_info.count
        orig_buffer = self.mem_utils.readBytes(self.cpu, exit_info.retval_addr, length) 
        self.pickleit(self.snap_name, exit_info, orig_buffer)

    def instrumentIO(self, callname):
        self.lgr.debug("prepInject in instrument IO, callname is %s" % callname);
        if callname.startswith('re') or callname == 'socketcall':
            SIM_run_alone(self.instrumentAlone, None)
        elif 'select' in callname:
            SIM_run_alone(self.instrumentSelect, None)
        else:
            self.lgr.error('preInject instrumentIO could not handle callname %s' % callname)

    def pickleit(self, name, exit_info, orig_buffer):
        self.lgr.debug('afl pickleit, begin')
        self.top.writeConfig(name)
        pickDict = {}
        pickDict['call_ip'] = self.call_ip
        pickDict['return_ip'] = self.return_ip
        pickDict['select_call_ip'] = self.select_call_ip
        pickDict['select_return_ip'] = self.select_return_ip
        pickDict['addr'] = exit_info.retval_addr
        if exit_info.sock_struct is not None:
            pickDict['size'] = exit_info.sock_struct.length
        else:
            pickDict['size'] = exit_info.count
        self.lgr.debug('afl pickleit save addr 0x%x size %d' % (pickDict['addr'], pickDict['size']))
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
