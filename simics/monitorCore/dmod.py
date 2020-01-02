#!/usr/bin/env python
import os
import re
import syscall
from simics import *

def nextLine(fh):
   retval = None
   while retval is None:
       line = fh.readline()
       if line is None or len(line) == 0:
           break
       if line.startswith('#'):
           continue
       if len(line.strip()) == 0:
           continue
       retval = line.strip('\n')
   return retval

class DmodSeek():
    def __init__(self, delta, pid, fd):
        self.delta = delta
        self.pid = pid
        self.fd = fd

class Dmod():
    class Fiddle():
        def __init__(self, match, was, becomes, cmds=[]):
            self.match = match
            self.was = was
            self.becomes = becomes        
            self.cmds = cmds        


    def __init__(self, top, path, mem_utils, cell_name, lgr):
        self.top = top
        self.kind = None
        self.fiddles = [] 
        self.mem_utils = mem_utils
        self.lgr = lgr
        self.stop_hap = None
        self.cell_name = cell_name
        self.path = path
        self.operation = None
        if os.path.isfile(path):
            with open(path) as fh:
               done = False
               kind_line = nextLine(fh) 
               parts = kind_line.split()
               self.kind = parts[0]
               if len(parts) > 1:
                   self.operation = parts[1]
               else:
                   self.lgr.error('Dmod command missing operation %s' % kind_line)
                   return
               self.lgr.debug('Dmod of kind %s  cell is %s' % (self.kind, self.cell_name))
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
               elif self.kind == 'sub_replace':
                   while not done:
                       match = nextLine(fh) 
                       if match is None:
                           done = True
                           break
                       was = nextLine(fh)
                       becomes = nextLine(fh) 
                       self.fiddles.append(self.Fiddle(match, was, becomes))
               elif self.kind == 'script_replace':
                   while not done:
                       match = nextLine(fh) 
                       if match is None:
                           done = True
                           break
                       was = nextLine(fh)
                       becomes = nextLine(fh) 
                       self.fiddles.append(self.Fiddle(match, was, becomes))
               else: 
                   print('Unknown dmod kind: %s' % self.kind)
                   return
            self.lgr.debug('Dmod loaded %d fiddles of kind %s' % (len(self.fiddles), self.kind))
        else:
            self.lgr.debug('Dmod, no file at %s' % path)

    def subReplace(self, cpu, s, addr):
        rm_this = None
        for fiddle in self.fiddles:
            #self.lgr.debug('Dmod checkString  %s to  %s' % (fiddle.match, s))
            try:
                match = re.search(fiddle.match, s, re.M|re.I)
            except:
                self.lgr.error('dmod subReplace re.search failed on match: %s, str %s' % (fiddle.match, s))
                return
            if match is not None:
                try:
                    was = re.search(fiddle.was, s, re.M|re.I)
                except:
                    self.lgr.error('dmod subReplace re.search failed on was: %s, str %s' % (fiddle.was, s))
                    return
                if was is not None:
                    self.lgr.debug('Dmod replace %s with %s in \n%s' % (fiddle.was, fiddle.becomes, s))
                    new_string = re.sub(fiddle.was, fiddle.becomes, s)
                    self.mem_utils.writeString(cpu, addr, new_string)
                else:
                    #self.lgr.debug('Dmod found match %s but not string %s in\n%s' % (fiddle.match, fiddle.was, s))
                    pass
                     
                rm_this = fiddle
                break
        return rm_this

    def scriptReplace(self, cpu, s, addr, pid, fd):
        rm_this = None
        checkline = None
        for fiddle in self.fiddles:
            lines = s.splitlines()
            for line in lines:
                #self.lgr.debug('Dmod check line %s' % (line))
                line = line.strip()
                if len(line) == 0 or line.startswith('#'):
                    continue
                elif line.startswith(fiddle.match):
                    checkline = line
                    break
                else:
                    return None
            if checkline is None:
                continue
            self.lgr.debug('Dmod checkString  %s to line %s' % (fiddle.match, checkline))
            try:
                was = re.search(fiddle.was, checkline, re.M|re.I)
            except:
                self.lgr.error('dmod subReplace re.search failed on was: %s, str %s' % (fiddle.was, checkline))
                return None
            if was is not None:
                self.lgr.debug('Dmod replace %s with %s in \n%s' % (fiddle.was, fiddle.becomes, checkline))
                new_string = re.sub(fiddle.was, fiddle.becomes, s)
                self.mem_utils.writeString(cpu, addr, new_string)
                new_line = re.sub(fiddle.was, fiddle.becomes, checkline)
                if len(checkline) != len(new_line):
                    delta = len(checkline) - len(new_line)
                    diddle_lseek = DmodSeek(delta, pid, fd)
                    operation = '_llseek'
                    call_params = syscall.CallParams(operation, diddle_lseek)        
                    self.top.runTo(operation, call_params, run=False, ignore_running=True)
                    self.lgr.debug('Dmod set syscall for lseek diddle delta %d pid %d fd %d' % (delta, pid, fd))
                else:
                    self.lgr.debug('replace caused no change %s\n%s' % (checkline, new_line))
            else:
                #self.lgr.debug('Dmod found match %s but not string %s in\n%s' % (fiddle.match, fiddle.was, s))
                pass
                 
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
            self.lgr.debug('dmod fullReplace %s in %s wrote %d bytes' % (fiddle.match, s, count))
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
        #self.lgr.debug('look for match of %s in %s' % (fiddle.match, s))
        if re.search(fiddle.match, s, re.M|re.I) is not None:
            #self.lgr.debug('found match of %s in %s' % (fiddle.match, s))
            rm_this = fiddle
            if re.search(fiddle.was, s, re.M|re.I) is not None:
                SIM_run_alone(self.stopAlone, fiddle)
        return rm_this

    def checkString(self, cpu, addr, count, pid=None, fd=None):
        retval = False
        byte_string, byte_array = self.mem_utils.getBytes(cpu, count, addr)
        if byte_array is None:
            self.lgr.debug('Dmod checkstring bytearray None from 0x%x' % addr)
            return retval
        s = ''.join(map(chr,byte_array))
        if self.kind == 'sub_replace':
            rm_this = self.subReplace(cpu, s, addr)
        elif self.kind == 'script_replace':
            rm_this = self.scriptReplace(cpu, s, addr, pid, fd)
        elif self.kind == 'full_replace':
            rm_this = self.fullReplace(cpu, s, addr)
        elif self.kind == 'match_cmd':
            rm_this = self.matchCmd(s)
        else:
            print('Unknown kind %s' % self.kind)
            return
        if rm_this is not None:
            self.lgr.debug('Dmod checkString found match cell %s path %s' % (self.cell_name, self.path))
            self.fiddles.remove(rm_this)
            if len(self.fiddles) == 0:
                self.lgr.debug('Dmod checkString removed last fiddle')
                retval = True
        return retval

    def stopHap(self, fiddle, one, exception, error_string):
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
        self.lgr.debug('Dmod stop hap')
        for cmd in fiddle.cmds:
            self.lgr.debug('run command %s' % cmd)
            SIM_run_command(cmd)
    
    def getOperation(self):
        return self.operation    
   
    def getPath(self):
        return self.path 
                    
        
if __name__ == '__main__':
    print('begin')
    d = Dmod('dog.dmod')
