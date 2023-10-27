#!/usr/bin/env python3
import os
import sys
import procTrace
import netLinks
import glob
class FileLinks():
    def __init__(self, path):
        open_tok = 'return from open tid'
        proc_trace_file = os.path.join(path, 'procTrace.txt')
        self.proc_trace = procTrace.ProcTrace(proc_trace_file) 
        trace_file = os.path.join(path, 'syscall_trace.txt')
        if not os.path.isfile(trace_file):
            trace_file = glob.glob('%s/syscall_trace*' % path)[0]
        self.readers = {}
        with open(trace_file) as fh:
            for line in fh:
                if open_tok in line:
                    if ' /proc' not in line and '.so' not in line and '/dev/null' not in line:
                        tid_id = netLinks.getTokValue(line, 'tid')
                        pname = self.proc_trace.getPname(tid_id)
                        #print('tid %s pname is %s' % (tid_id, pname))
                        fname = netLinks.getTokValue(line, 'file')
                        mode = netLinks.getTokValue(line, 'mode')
                        if fname not in self.readers:
                            self.readers[fname] = []
                        if pname not in self.readers[fname]:
                            self.readers[fname].append(pname)
    def showFileShare(self):
        for fname in self.readers:
            print('%s' % fname)
            for reader in self.readers[fname]:
                print('\t%s' % reader)

if __name__ == '__main__':
    traces = sys.argv[1]
    fl = FileLinks(traces)
    fl.showFileShare()
 
            
