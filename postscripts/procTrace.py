#!/usr/bin/env python
import os
class ProcTrace():
    def __init__(self, fname):
        self.pmap = {}
        with open(fname) as fh:
            for line in fh:
                parts = line.split()
                pid_id = None
                if len(parts) > 1:
                    pidtok = parts[0]
                    if '-' in pidtok:
                        pid_id = pidtok
                    else:
                        try:
                            dumb = int(pidtok)
                            pid_id = pidtok
                        except:
                            pass
                    if pid_id is not None:
                        self.pmap[pid_id] = parts[1]
                        #print('set %s to %s' % (pid_id, parts[1]))
    def getPname(self, pid):
        for pid_id in self.pmap:
            p = pid_id
            if '-' in pid_id:
                p = pid_id.split('-')[0]
            if pid == p:
                return self.pmap[pid_id]
        return None

if __name__ == "__main__":
    pt = ProcTrace('traces/procTrace.txt')
    p = pt.getPname('1326')
    print('got %s' % p)
