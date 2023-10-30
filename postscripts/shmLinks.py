#!/usr/bin/env python3
import procTrace
import os
import sys
import glob
import netLinks
'''
IPC keys  for SHMGET
'''
class SHMLinks():
    def __init__(self, path):
        self.shmsize = {}
        self.keymap = {}
        ipc_tok = 'ipc SHMGET' 
        proc_trace_file = os.path.join(path, 'procTrace.txt')
        print('Use procTrace from %s' % proc_trace_file)
        self.proc_trace = procTrace.ProcTrace(proc_trace_file) 
        syscall_file = os.path.join(path, 'syscall_trace.txt')
        if not os.path.isfile(syscall_file):
            syscall_file = glob.glob('%s/syscall_trace*' % path)[0]
        with open(syscall_file) as fh:
            for line in fh:
                if ipc_tok in line:
                    parts = line.split()
                    tid_id = netLinks.getTokValue(line, 'tid')
                    if tid_id is not None:
                        pname = self.proc_trace.getPname(tid_id)
                        if pname is None:
                            print('no pname for %s' % tid_id)
                            pname = 'unknown'
                    else:
                        print('could not find tid in %s' % line)
                        exit(1)
                    shm_key = netLinks.getTokValue(line, 'key')
                    if shm_key is not None:
                        if shm_key not in self.keymap:
                            self.keymap[shm_key] = []
                        if pname not in self.keymap[shm_key]:
                            self.keymap[shm_key].append(pname)
                        shm_size = netLinks.getTokValue(line,'size')
                        if shm_size is not None:
                            self.shmsize[shm_key] = int(shm_size)

    def showMap(self):
        for key in sorted(self.keymap):
            line = key
            if key in self.shmsize:
                 line = line + '(0x%x)' % self.shmsize[key]
            for pname in self.keymap[key]:
                line = line + ' ' + pname
            print(line)

if __name__ == "__main__":
    traces = sys.argv[1]
    ipc = SHMLinks(traces)
    ipc.showMap()
            
                 
