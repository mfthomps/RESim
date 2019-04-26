import idc
import idautils
import idaapi
import os
import json
import gdbProt
class OrigAnalysis():

    def __init__(self, path):
        self.root_prefix = '/mnt/vdr_img/rootfs'
        self.funs = {}
        self.funnames = []
        funfile = path+'.funs'
        if os.path.isfile(funfile):
            print('function file: %s' % funfile)
            with open(funfile) as fh:
                jfuns = json.load(fh)
                for sfun in jfuns:
                    fun = int(sfun)
                    self.funs[fun] = jfuns[sfun]
                    name = str(jfuns[sfun]['name'])
                    self.funnames.append(name)

    def getFun(self, ip):
        for fun in self.funs:
            if ip >= self.funs[fun]['start'] and ip <= self.funs[fun]['end']:
                return fun
            #print('ip 0x%x start 0x%x - 0x%x' % (ip, self.funs[fun]['start'], self.funs[fun]['end']))
        return None


    def origFun(self, ip):
        print('look for fun having ip 0x%x' % ip)
        fun = self.getFun(ip)
        if fun is None:
            simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.getSO(0x%x)");' % ip) 
            print('No function found.  Check load for: %s' % simicsString)
            if ':' in simicsString:
                sofile, start_end = str(simicsString).rsplit(':', 1)
                print('sofile is %s start_end is %s' % (sofile, start_end))
                if '-' not in start_end:
                    print('Bad response from getSO: %s' % simicsString)
                    return
                full = os.path.join(self.root_prefix, sofile[1:])
                sopath = self.getFunPath(full)
                start, end = start_end.split('-')
                start = int(start, 16)
                end = int(end, 16)
                self.add(sopath, start)
                fun = self.getFun(ip)
                print('start 0x%x end 0x%x' % (start, end))
                idaapi.analyze_area(start, end)
                for fun in sorted(self.funs):
                    if fun >= start and fun <= end:
                        name = str(self.funs[fun]['name'])
                        nea = idaapi.get_name_ea(idaapi.BADADDR, name)
                        if nea != idaapi.BADADDR:
                           name = name+'_so' 
                        idc.MakeName(int(fun), name)
                        print('made name for 0x%x  %s' % (int(fun), name))
                for fun in self.funs:
                    if fun >= start and fun <= end:
                        #print('fun 0x%x name <%s>' % (fun, name))
                        idc.MakeFunction(fun, idaapi.BADADDR)
        
        elif fun is not None:
                print('Do one fun 0x%x' % fun)
                for i in range(self.funs[fun]['start'], self.funs[fun]['end']):
                    idc.MakeUnkn(i, 1)
                idaapi.auto_mark_range(self.funs[fun]['start'], self.funs[fun]['end'], 25)
                idaapi.autoWait()
                return fun
        return None

    def getFunPath(self, path):
        fun_path = path+'.funs'
        if not os.path.isfile(fun_path):
            ''' No functions file, check for symbolic links '''
            print('is link? %s' % path)
            if os.path.islink(path):
                actual = os.path.join(os.path.dirname(path), os.readlink(path))
                print('actual  %s' % actual)
                fun_path = actual+'.funs'
        return fun_path
            
    def add(self, funfile, offset):
        if os.path.isfile(funfile):
            with open(funfile) as fh:
                print('IDAFuns add for path %s' % funfile)
                newfuns = json.load(fh)
                for f in newfuns:
                    fun = int(f)+offset
                    self.funs[fun] = {}
                    self.funs[fun]['start'] = fun
                    self.funs[fun]['end'] = newfuns[f]['end']+offset
                    name = str(newfuns[f]['name'])
                    if name in self.funnames:
                        name = name+'_so'
                        self.funnames.append(name)
                    self.funs[fun]['name'] = name
                    #print('added %s' % name)
                    #self.lgr.debug('idaFun add was %s %x %x   now %x %x %x' % (f, newfuns[f]['start'], newfuns[f]['end'], fun, self.funs[fun]['start'], self.funs[fun]['end']))
        else:
            print('IDAFuns NOTHING at %s' % funfile)

