#!/usr/bin/env python3
import os
class ProcTrace():
    def __init__(self, fname):
        self.pmap = {}
        with open(fname) as fh:
            for line in fh:
                parts = line.split()
                tid_id = None
                if len(parts) > 1:
                    tidtok = parts[0]
                    if '-' in tidtok:
                        tid_id = tidtok
                    else:
                        try:
                            dumb = int(tidtok)
                            tid_id = tidtok
                        except:
                            pass
                    if tid_id is not None:
                        self.pmap[tid_id] = parts[1]
                        #print('set %s to %s' % (tid_id, parts[1]))
    def getPname(self, tid):
        for tid_id in self.pmap:
            p = tid_id
            if '-' in tid_id:
                p = tid_id.split('-')[0]
            if tid == p:
                return self.pmap[tid_id]
        return None

if __name__ == "__main__":
    pt = ProcTrace('traces/procTrace.txt')
    p = pt.getPname('1326')
    print('got %s' % p)
