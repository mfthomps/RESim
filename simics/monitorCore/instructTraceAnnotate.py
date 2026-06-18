import os
class InstructTraceAnnotate():
    def __init__(self, top, fname, lgr):
        self.fname = fname
        self.top = top
        self.lgr = lgr
        outname = fname+'.annotated'
        self.out_fh = open(outname, 'w')

        self.annotate()

    def annotate(self):
        if not os.path.isfile(self.fname):
            print('No trace file found at %s' % self.fname) 
            return
        if self.top.getFunMgr() is None:
            print('No funMgr.  Debugging?')
            return
        prev_so = None
        prev_line = None
        prev_fun = None
        fun = None
        with open(self.fname) as fh:
            for line in fh:
                line = line.strip()
                if line.startswith('Starting cycle:'):
                    cycles = int(line.split(':')[1].split()[0], 16)
                    self.record(line)
                elif line.startswith('return from kernel'):
                    cycles = int(line.split(':')[1].split()[0], 16)
                    self.record(line)
                    prev_so = None
                    prev_fun = None
                elif line.startswith('into kernel'):
                    if prev_line is not None:
                        self.record(prev_line)
                        self.record(line)
                elif line.startswith('inst:'):
                    vaddr_s = line.split('<v:')[1].split('>')[0] 
                    vaddr = int(vaddr_s, 16)
                    if self.top.isKernel(vaddr):
                        continue
                    counter = line.split(']')[0].split()[-1]
                    after = line.split('>')[2]
                    instruct = after.split(maxsplit=1)[1].strip()
                    #print('0x%x %s' % (vaddr, instruct))
                    new_line = '%x 0x%20x %35s' % (cycles, vaddr, instruct)
                    lib = self.top.getSO(vaddr, just_name=True)
                    if lib is None:
                        #print('lib is None for vaddr 0x%x' % vaddr)
                        if prev_so is not None:
                           self.record(prev_line)
                           self.record(new_line)
                           prev_so = None
                        prev_line = new_line 
                        fun = None
                        pass
                    else:
                        fun = self.top.getFunName(vaddr)
                        if lib != prev_so:
                            new_line = '%s %30s %20s' % (new_line, os.path.basename(lib), fun)
                            if prev_line is not None:
                                self.record(prev_line)
                            self.record(new_line)
                            prev_so = lib
                            prev_line = None
                        else:
                            new_line = '%s %30s %20s' % (new_line, os.path.basename(lib), fun)
                            if fun is not None and fun != prev_fun and 'libc' not in lib and 'libstd' not in lib:         
                                if prev_line is not None and prev_line != new_line:
                                    self.record(prev_line+' x')
                                self.record(new_line)
                            else:
                                prev_line = new_line 
                        prev_fun = fun
                    cycles = cycles + 1

    def record(self, line):
        print(line) 
        self.out_fh.write(line+'\n')
