#!/usr/bin/env python
import os
import sys
def getUnsigned(val):
    return val & 0xFFFFFFFF

class traceCycles():
    def __init__(self, fname):
        self.trace_map = {}
        self.trace_start_cycle = None
        self.monitor_cycle_delta = None
        self.first_syscall = None
        lno =0
        with open(fname) as fh:
            for line in fh:
                 if self.trace_start_cycle is None and line.startswith('start cycle'):
                     cycle = line.split()[2].strip()
                     self.trace_start_cycle = int(cycle, 16)
                 if line.startswith('inst:'):
                     lno += 1
                     if self.first_syscall is None and 'int 128' in line:
                         self.first_syscall = lno
                     parts = line.split()
                     cycle = parts[4]
                     cycle = cycle[:len(cycle)-1]
                     self.trace_map[cycle] = lno
                     #print('%s %s' % (lno, cycle)) 
            print('%d lines' % lno)

    def getLineNumber(self, cycle):
        ''' our cycles are strings, as is the given cycles '''
        cycle = int(cycle, 16) 
        if cycle == 0:
            line_number = 0
        else:
            new_cycle = getUnsigned(cycle) - self.monitor_cycle_delta
            cycle_str = '%x' % getUnsigned(new_cycle)
            print('given %x, new 0x%x  %s' % (cycle, new_cycle, cycle_str))
            line_number = self.trace_map[cycle_str]
            print('line for %s is %s' % (cycle, line_number))
        return line_number

    def getFirstSyscall(self):
        return self.first_syscall

    def setMonitorCycle(self, cycle):
        ''' monitor cycles start counting before trace cycles.  trace_cycles is larger '''
        self.monitor_cycle_delta = self.trace_start_cycle - cycle
        print('given %x, our start %x, delta %x' % (cycle, self.trace_start_cycle, self.monitor_cycle_delta))

if __name__ == '__main__':    
    fname = '/tmp/CROMU_00046-6-1-58-0-trace.log'
    tc = traceCycles(fname)
    monitor_start_cycle = 0x4cd0bae229 
    tc.setMonitorCycle(monitor_start_cycle)
    l = tc.getLineNumber('5d0fa52')
    print l
