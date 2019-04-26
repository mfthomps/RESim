#!/usr/bin/env python
import os
import re
from simics import *

def nextLine(fh):
   retval = None
   while retval is None:
       line = fh.readline()
       if line is None or len(line) == 0:
           break
       if line.strip().startswith('#'):
           continue
       retval = line.strip('\n')
   return retval

class Diddler():
    class Fiddle():
        def __init__(self, match, was, becomes, cmds=[]):
            self.match = match
            self.was = was
            self.becomes = becomes        
            self.cmds = cmds        
    def __init__(self, path, mem_utils, lgr):
        self.kind = None
        self.fiddles = [] 
        self.mem_utils = mem_utils
        self.lgr = lgr
        self.stop_hap = None
        if os.path.isfile(path):
            with open(path) as fh:
               done = False
               self.kind = nextLine(fh) 
               if self.kind == 'full_replace':
                   match = nextLine(fh) 
                   becomes=''
                   while not done:
                      line = fh.readline()
                      if line is None or len(line)==0:
                          done = True
                          break
                      if len(becomes)==0:
                          becomes=line
                      else:
                          becomes=becomes+line
                   self.fiddles.append(self.Fiddle(match, None, becomes))
               elif self.kind == 'match_cmd':
                   match = nextLine(fh) 
                   was = nextLine(fh) 
                   cmds=[] 
                   while not done:
                      line = nextLine(fh)
                      if line is None or len(line)==0:
                          done = True
                          break
                      cmds.append(line)
                   self.fiddles.append(self.Fiddle(match, was, None, cmds=cmds))
               else: 
                   while not done:
                       match = nextLine(fh) 
                       if match is None:
                           done = True
                           break
                       was = nextLine(fh)
                       becomes = nextLine(fh) 
                       self.fiddles.append(self.Fiddle(match, was, becomes))
            self.lgr.debug('Diddler loaded %d fiddles of kind %s' % (len(self.fiddles), self.kind))
        else:
            self.lgr.debug('Diddler, no file at %s' % path)

    def subReplace(self, cpu, s, addr):
        rm_this = None
        for fiddle in self.fiddles:
            #self.lgr.debug('Diddle checkString  %s to  %s' % (fiddle.match, s))
            if fiddle.match in s:
                if fiddle.was in s:
                    self.lgr.debug('Diddle replace %s with %s in \n%s' % (fiddle.was, fiddle.becomes, s))
                    new_string = s.replace(fiddle.was, fiddle.becomes)
                    self.mem_utils.writeString(cpu, addr, new_string)
                else:
                    self.lgr.debug('Diddle found match %s but not string %s in\n%s' % (fiddle.match, fiddle.was, s))
                     
                rm_this = fiddle
                break
        return rm_this

    def fullReplace(self, cpu, s, addr):
        rm_this = None
        fiddle = self.fiddles[0]
        if fiddle.match in s:
            count = len(fiddle.becomes)
            self.mem_utils.writeString(cpu, addr, fiddle.becomes)
            esp = self.mem_utils.getRegValue(cpu, 'esp')
            count_addr = esp + 3*self.mem_utils.WORD_SIZE
            self.mem_utils.writeWord(cpu, count_addr, count)
            #cpu.iface.int_register.write(reg_num, count)
            self.lgr.debug('diddle fullReplace %s in %s wrote %d bytes' % (fiddle.match, s, count))
            rm_this = fiddle
            #SIM_break_simulation('deeedee')
        return rm_this

    def stopAlone(self, fiddle):
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap, fiddle)
        SIM_break_simulation('matchCmd')

    def matchCmd(self, s):
        ''' The match lets us stop looking regardless of whether or not the values are
            bad.  The "was" tells us a bad value, i.e., reason to run commands '''
        rm_this = None
        fiddle = self.fiddles[0]
        self.lgr.debug('look for match of %s in %s' % (fiddle.match, s))
        if re.search(fiddle.match, s, re.M|re.I) is not None:
            self.lgr.debug('found match of %s in %s' % (fiddle.match, s))
            rm_this = fiddle
            if re.search(fiddle.was, s, re.M|re.I) is not None:
                SIM_run_alone(self.stopAlone, fiddle)
        return rm_this

    def checkString(self, cpu, addr, count):
        retval = False
        byte_string, byte_array = self.mem_utils.getBytes(cpu, count, addr)
        s = ''.join(map(chr,byte_array))
        if self.kind == 'sub_replace':
            rm_this = self.subReplace(cpu, s, addr)
        elif self.kind == 'full_replace':
            rm_this = self.fullReplace(cpu, s, addr)
        elif self.kind == 'match_cmd':
            rm_this = self.matchCmd(s)
        else:
            print('Unknown kind %s' % self.kind)
            return
        if rm_this is not None:
            self.fiddles.remove(rm_this)
            if len(self.fiddles) == 0:
                self.lgr.debug('Diddler checkString removed last fiddle')
                retval = True
        return retval

    def stopHap(self, fiddle, one, exception, error_string):
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
        self.lgr.debug('Diddler stop hap')
        for cmd in fiddle.cmds:
            SIM_run_command(cmd)
        
    
                    
        
if __name__ == '__main__':
    print('begin')
    d = Diddler('dog.diddle')
