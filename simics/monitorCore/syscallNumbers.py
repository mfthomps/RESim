import os
class SyscallNumbers():
    def __init__(self, fpath, lgr):
        self.syscalls = {}
        self.callnums = {}
        self.lgr = lgr
        if fpath.endswith('ia64.tbl'):
            self.fromTbl(fpath)
        elif fpath.endswith('arm64.tbl'):
            self.fromArm64Tbl(fpath)
        else:
            self.fromInclude(fpath)

    def fromTbl(self, fpath):
        with open(fpath) as fh:
            for line in fh:
                parts = line.split()
                callnum = int(parts[0])
                name = parts[1].strip()
                self.syscalls[callnum] = name
                self.callnums[name] = callnum

    def fromArm64Tbl(self, fpath):
        with open(fpath) as fh:
            for line in fh:
                parts = line.split()
                try:
                    callnum = int(parts[0])
                except:
                    continue
                name = parts[1].strip()
                self.syscalls[callnum] = name
                self.callnums[name] = callnum
        if 'open' not in self.callnums:
            # ug
            if 'openat' in self.callnums:
                callnum = self.callnums['openat']
                self.callnums['open'] = callnum
                self.syscalls[callnum] = ['open']
            else:
                self.lgr.error('SyscallNumbers no open???')
                self.lgr.error('%s' % str(self.callnums))

    def fromInclude(self, fpath):
        hackvals = {}
        if not os.path.isfile(fpath):
            print('ERROR *** Could not find unistd file at %s ***' % fpath)
            return
        with open(fpath) as fh:
            for line in fh:
                if '__NR_' in line:
                    parts = line.split()
                    if parts[0] != '#define':
                        continue
                    if '__NR_syscall_max' in line:
                        continue
                    nr = parts[1][5:]
                    ''' check for generated unistd file '''
                    if nr.startswith('ia32_'):
                        nr = nr[5:]
                    try:
                        callnum = int(parts[2])
                        hackvals[parts[1]] = callnum
                    except:
                        #print('failed to handle %s' % line)
                        #s = parts[2]
                        express = line[line.find("(")+1:line.find(")")]
                        try:
                            sym, offset = express.split('+')
                        except:
                            #lgr.debug('No + in %s from \n%s' % (express, line))
                            continue
                        base = hackvals[sym]
                        try:
                            callnum = base + int(offset)
                        except:
                            #lgr.debug('expected base10 int in %s' % line)
                            continue
                    #lgr.debug('assign call # %d to %s' % (callnum, nr))
                    self.syscalls[callnum] = nr
                    self.callnums[nr] = callnum
                     

