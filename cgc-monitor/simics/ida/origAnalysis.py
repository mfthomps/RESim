import idc
import idaapi
import os
import json
class OrigAnalysis():
    def __init__(self, path):
        self.funs = None
        funfile = path+'.funs'
        if os.path.isfile(funfile):
            with open(funfile) as fh:
                self.funs = json.load(fh) 

    def origFun(self, ip):
        print('look for fun having ip 0x%x' % ip)
        for f in self.funs:
            #print('compare 0x%x to 0x%x 0x%x' % (ip, self.funs[f]['start'], self.funs[f]['end']))
            if ip >= self.funs[f]['start'] and ip <= self.funs[f]['end']:
                print('0x%x in function %s : 0x%x' % (ip, self.funs[f]['name'], self.funs[f]['start']))
                for i in range(self.funs[f]['start'], self.funs[f]['end']):
                    idc.MakeUnkn(i, 1)
                idaapi.auto_mark_range(self.funs[f]['start'], self.funs[f]['end'], 25)
                idaapi.autoWait()
                return 1
