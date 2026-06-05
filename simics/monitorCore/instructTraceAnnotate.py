import os
class InstructTraceAnnotate():
    def __init__(self, top, fname, lgr):
        self.fname = fname
        self.top = top
        self.lgr = lgr
        self.annotate()
    def annotate(self, fname=None):
        if not os.path.isfile(self.fname):
            print('No trace file found at %s' % self.fname) 
            return

        prev_so = None
        prev_line = None
        fun = None
        with open(self.fname) as fh:
            for line in fh:
                if line.startswith('inst:'):
                    vaddr_s = line.split('<v:')[1].split('>')[0] 
                    vaddr = int(vaddr_s, 16)
                    after = line.split('>')[2]
                    instruct = after.split(maxsplit=1)[1].strip()
                    #print('0x%x %s' % (vaddr, instruct))
                    new_line = '0x%20x %35s' % (vaddr, instruct)
                    lib = self.top.getSO(vaddr, just_name=True)
                    if lib is None:
                        #print('lib is None for vaddr 0x%x' % vaddr)
                        if prev_so is not None:
                           print(prev_line)
                           print(new_line)
                        prev_line = new_line 
                        fun = None
                        pass
                    else:
                        fun = self.top.getFunName(vaddr)
                        if lib != prev_so:
                            new_line = '%s %30s %20s' % (new_line, os.path.basename(lib), fun)
                            if prev_line is not None:
                                print(prev_line)
                            print(new_line)
                            prev_so = lib
                            prev_line = None
                        else:
                            new_line = '%s %30s %20s' % (new_line, os.path.basename(lib), fun)
                            prev_line = new_line 
