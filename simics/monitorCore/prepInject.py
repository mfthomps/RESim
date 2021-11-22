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
        self.prepInject(snap_name)

    def prepInject(self, snap_name):
        ''' Use runToInput to find location of desired input call.  Set callback to instrument the call and return '''
        self.lgr.debug('afl prepInject snap %s' % snap_name)
        f1 = stopFunction.StopFunction(self.instrumentIO, [snap_name], nest=False)
        flist = [f1]
        self.top.runToInput(self.fd, flist_in=flist, count=self.count)

    def instrumentAlone(self, snap_name): 
        self.top.removeDebugBreaks(keep_watching=False, keep_coverage=True)
        ''' go forward one to user space and record the return IP '''
        SIM_run_command('pselect %s' % self.cpu.name)
        SIM_run_command('si')
        self.return_ip = self.top.getEIP(self.cpu)
        ret_cycle = self.cpu.cycles
        pid = self.top.getPID()
        self.lgr.debug('instrument snap_name %s stepped to return IP: 0x%x pid:%d cycle is 0x%x' % (snap_name, self.return_ip, pid, self.cpu.cycles))
        ''' return to the call to record that IP and original data in the buffer'''
        frame, cycle = self.top.getRecentEnterCycle()
        exit_info = self.top.getMatchingExitInfo()
        previous = cycle - 1
        SIM_run_command('skip-to cycle=%d' % previous)
        self.call_ip = self.top.getEIP(self.cpu)
        pid = self.top.getPID()
        if exit_info.sock_struct is not None:
            length = exit_info.sock_struct.length
        else:
            length = exit_info.count
        orig_buffer = self.mem_utils.readBytes(self.cpu, exit_info.retval_addr, length) 
        self.lgr.debug('instrument  skipped to call IP: 0x%x pid:%d callnum: %d cycle is 0x%x' % (self.call_ip, pid, frame['syscall_num'], self.cpu.cycles))
        ''' skip back to return so the snapshot is ready to inject input '''
        SIM_run_command('skip-to cycle=%d' % ret_cycle)
        self.pickleit(snap_name, exit_info, orig_buffer)

    def instrumentIO(self, snap_name):
        self.lgr.debug("in instrument IO");
        SIM_run_alone(self.instrumentAlone, snap_name)

    def pickleit(self, name, exit_info, orig_buffer):
        self.lgr.debug('afl pickleit, begin')
        self.top.writeConfig(name)
        pickDict = {}
        pickDict['call_ip'] = self.call_ip
        pickDict['return_ip'] = self.return_ip
        pickDict['addr'] = exit_info.retval_addr
        if exit_info.sock_struct is not None:
            pickDict['size'] = exit_info.sock_struct.length
        else:
            pickDict['size'] = exit_info.count
        self.lgr.debug('afl pickleit save addr 0x%x size %d' % (pickDict['addr'], pickDict['size']))
        ''' Otherwise console has no indiation of when done. '''
        print('Configuration file saved, ok to quit.')

        if exit_info.fname_addr is not None:
            count = self.mem_utils.readWord32(self.cpu, exit_info.count)
            pickDict['addr_addr'] = exit_info.fname_addr
            pickDict['addr_size'] = count

        pickDict['orig_buffer'] = orig_buffer
        afl_file = os.path.join('./', name, self.cell_name, 'afl.pickle')
        pickle.dump( pickDict, open( afl_file, "wb") ) 
