#!/usr/bin/env python 
import procTrace
import os
import sys
import glob
import netLinks
'''
IPC keys seem superfolous to naming.  Queue IDs are system unique?  
(Would expect process local)
'''
class IPCLinks():
    def __init__(self, path):
        self.keymap = {}
        ipc_tok = 'ipc MSGRCV' 
        ipc_tok2 = 'ipc MSGSND' 
        proc_trace_file = os.path.join(path, 'procTrace.txt')
        print('Use procTrace from %s' % proc_trace_file)
        self.proc_trace = procTrace.ProcTrace(proc_trace_file) 
        syscall_file = os.path.join(path, 'syscall_trace.txt')
        if not os.path.isfile(syscall_file):
            syscall_file = glob.glob('%s/syscall_trace*' % path)[0]
        with open(syscall_file) as fh:
            for line in fh:
                if ipc_tok in line or ipc_tok2 in line:
                    parts = line.split()
                    pid_id = netLinks.getTokValue(line, 'pid')
                    if pid_id is not None:
                        pname = self.proc_trace.getPname(pid_id)
                        if pname is None:
                            print('no pname for %s' % pid_id)
                            pname = 'unknown'
                    else:
                        print('could not find pid in %s' % line)
                        exit(1)
                    quid = netLinks.getTokValue(line, 'quid')
                    if quid is not None:
                        if quid not in self.keymap:
                            self.keymap[quid] = []
                        if pname not in self.keymap[quid]:
                            self.keymap[quid].append(pname)

    def showMap(self):
        for key in sorted(self.keymap):
            line = key
            for pname in self.keymap[key]:
                line = line + ' ' + pname
            print line

if __name__ == "__main__":
    traces = sys.argv[1]
    ipc = IPCLinks(traces)
    ipc.showMap()
            
                 
