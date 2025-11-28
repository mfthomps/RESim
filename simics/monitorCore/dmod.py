#!/usr/bin/env python
import os
import re
import syscall
from simics import *
import openFlags
import resimUtils
'''
Manage one Dmod.  
'''
def nextLine(fh, hash_ok=False):
   retval = None
   while retval is None:
       line = fh.readline()
       if line is None or len(line) == 0:
           break
       if line.startswith('#') and not hash_ok:
           continue
       if len(line.strip()) == 0:
           continue
       retval = line.strip('\n')
   return retval

class DmodSeek():
    def __init__(self, delta, tid, fd):
        self.delta = delta
        self.tid = tid
        self.fd = fd

class Dmod():
    class Fiddle():
        ''' TBD replace this class with kind-specific classes having clear (non-overloaded) semantics'''
        def __init__(self, match, was, becomes, cmds=[], decode=True):
            self.match = match
            if was is not None:
                self.was = was
                if type(becomes) == bytes:
                    if decode:
                        becomes = becomes.decode()
                    else:
                        self.becomes = becomes
                if becomes is not None and decode:
                    mod = becomes.replace('\\n', '\n')
                    self.becomes = mod
                elif decode:
                    self.becomes = None
            else:
                self.was = None
                self.becomes = None
            self.cmds = cmds        


    def __init__(self, top, path, mem_utils, cell_name, comm, run_from_snap, fd_mgr, path_prefix, lgr, primary=None):
        self.top = top
        self.kind = None
        self.fiddle = None
        self.mem_utils = mem_utils
        self.lgr = lgr
        self.stop_hap = None
        self.cell_name = cell_name
        self.path = path
        self.run_from_snap = run_from_snap
        self.fd_mgr = fd_mgr
        if comm is None:
            self.comm = []
        else:
            self.comm = [comm]
        self.operation = None
        self.count = 1
        self.fname_addr = None
        self.break_on_dmod = False
        self.path_prefix = path_prefix
        self.length = None
        self.primary = primary
        self.secondary_count = 0

        # used for callback when comm of the dmod is first scheduled
        self.op_set = None
        self.call_params = None

        self.open_replace_fh = {}
        self.open_replace_fname = {}
  
        self.bytes_file = None

        if os.path.isfile(path):
            with open(path) as fh:
               done = False
               kind_line = nextLine(fh) 
               parts = kind_line.split()
               self.kind = parts[0]
               if len(parts) > 1:
                   self.operation = parts[1]
               else:
                   self.lgr.error('dmod %s command missing operation %s' % (path, kind_line))
                   return
               start_part = 2
               if len(parts) > start_part:
                   try:
                       self.count = int(parts[start_part])
                       start_part = start_part + 1
                   except:
                       if '=' not in parts[2]:
                           self.lgr.error('Expected count in kind line: %s' % kind_line)
                           return
                   self.lgr.debug('dmod start_part is %d len %d' % (start_part, len(parts)))
                   if len(parts) > start_part:
                       for item in parts[start_part:]:
                           key, value = resimUtils.getKeyValue(item)
                           self.lgr.debug('dmod key <%s> value %s' % (key, value))
                           if key is None:
                               self.lgr.error('Expected key=value in %s' % item)
                               return
                           if key == 'count':
                               self.count = int(value)
                           elif key == 'comm':
                               parts = value.split(';')
                               self.comm = parts
                           elif key == 'break':
                               if value.lower() == 'true':
                                   self.break_on_dmod = True
                           elif key == 'length':
                               self.length = int(value)
                           elif key == 'bytes_file':
                               self.bytes_file = value

               self.lgr.debug('dmod %s of kind %s  cell is %s count is %d comm: %s' % (path, self.kind, self.cell_name, self.count, str(self.comm)))
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
                   self.fiddle = self.Fiddle(match, 'full_replace', becomes)
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
                   self.fiddle = self.Fiddle(match, was, None, cmds=cmds)
               elif self.kind == 'sub_replace':
                   while not done:
                       match = nextLine(fh) 
                       if match is None:
                           done = True
                           break
                       was = nextLine(fh, hash_ok=True)
                       becomes = nextLine(fh, hash_ok=True) 
                       self.fiddle = self.Fiddle(match, was, becomes)
               elif self.kind == 'script_replace':
                   while not done:
                       match = nextLine(fh) 
                       if match is None:
                           done = True
                           break
                       was = nextLine(fh)
                       becomes = nextLine(fh) 
                       self.fiddle = self.Fiddle(match, was, becomes)
               elif self.kind == 'open_replace':
                   match = nextLine(fh) 
                   becomes_file = nextLine(fh)
                   if not os.path.isfile(becomes_file):
                       self.lgr.error('Dmod, open_replace expected file name, could not find %s' % becomes_file)
                       return
                   #becomes = None
                   #with open(becomes_file, 'rb') as bf_fh:
                   #    becomes = bf_fh.read()
                   self.fiddle = self.Fiddle(match, 'open_replace', becomes_file)
               elif self.kind == 'syscall':
                   match = nextLine(fh) 
                   self.fiddle = self.Fiddle(match, None, None)

               else: 
                   print('Unknown dmod kind: %s' % self.kind)
                   return
            self.lgr.debug('dmod loaded fiddle of kind %s' % (self.kind))
        else:
            self.lgr.error('Dmod, no file at %s' % path)

    def subReplace(self, cpu, s, addr):
        rm_this = False
        self.lgr.debug('dmod subReplace  %s to  %s' % (self.fiddle.match, s))
        try:
            match = re.search(self.fiddle.match, s, re.M|re.I)
        except:
            self.lgr.error('dmod subReplace re.search failed on match: %s, str %s' % (self.fiddle.match, s))
            return False
        if match is not None:
            try:
                was = re.search(self.fiddle.was, s, re.M|re.I)
            except:
                self.lgr.error('dmod subReplace re.search failed on was: %s, str %s' % (self.fiddle.was, s))
                return
            if was is not None:
                entire_match = was.group(0)
                new_string = re.sub(entire_match, self.fiddle.becomes, s, re.M|re.I)
                self.lgr.debug('dmod cell: %s replace %s with %s. Orig len %d new len %d in \n%s' % (self.cell_name, self.fiddle.was, self.fiddle.becomes, len(s), len(new_string), s))
                self.lgr.debug('new_string: %s' % new_string)
                self.top.writeString(addr, new_string, target_cpu=cpu)
            else:
                self.lgr.debug('dmod found match %s but not string %s in\n%s' % (self.fiddle.match, self.fiddle.was, s))
                pass
                 
            rm_this = True
        return rm_this

    def scriptReplace(self, cpu, s, addr, tid, fd):
        rm_this = False
        checkline = None
        lines = s.splitlines()
        for line in lines:
            #self.lgr.debug('dmod check line %s' % (line))
            line = line.strip()
  
            if len(line) == 0 or line.startswith('#'):
                continue
            elif line.startswith(self.fiddle.match):
                checkline = line
                break
        if checkline is None:
            return False
        #self.lgr.debug('dmod checkString  %s to line %s' % (self.fiddle.match, checkline))
        try:
            was = re.search(self.fiddle.was, checkline, re.M|re.I)
        except:
            self.lgr.error('dmod subReplace re.search failed on was: %s, str %s' % (self.fiddle.was, checkline))
            return None
        if was is not None:
            self.lgr.debug('dmod replace %s with %s in \n%s' % (self.fiddle.was, self.fiddle.becomes, checkline))
            new_string = re.sub(self.fiddle.was, self.fiddle.becomes, s)
            #self.lgr.debug('newstring is: %s' % new_string)
            self.top.writeString(addr, new_string, target_cpu=cpu)
            new_line = re.sub(self.fiddle.was, self.fiddle.becomes, checkline)
            if len(checkline) != len(new_line):
                ''' Adjust future _lseek calls, which are caught in syscall.py '''
                delta = len(checkline) - len(new_line)
                diddle_lseek = DmodSeek(delta, tid, fd)
                operation = ['_llseek', 'close']
                call_params = syscall.CallParams('DmodReplace', operation, diddle_lseek)        
                cell = self.top.getCell(cell_name=self.cell_name)
                ''' Provide explicit cell to avoid defaulting to the contextManager.  Cell is typically None.'''
                self.top.runTo(operation, call_params, run=False, ignore_running=True, cell_name=self.cell_name, cell=cell)
                self.lgr.debug('dmod set syscall for lseek diddle delta %d tid:%s fd %d' % (delta, tid, fd))
            else:
                self.lgr.debug('replace caused no change %s\n%s' % (checkline, new_line))
        else:
            #self.lgr.debug('dmod found match %s but not string %s in\n%s' % (fiddle.match, fiddle.was, s))
            pass
             
        rm_this = True
        return rm_this

    def fullReplace(self, cpu, s, addr):
        rm_this = False
        #self.lgr.debug('dmod fullReplace is %s in %s' % (self.fiddle.match, s))
        if self.fiddle.match in s:
            self.lgr.debug('dmod got match')
            count = len(self.fiddle.becomes)
            self.mem_utils.writeString(cpu, addr, self.fiddle.becomes, target_cpu=cpu)
            if self.operation == 'write':
                esp = self.mem_utils.getRegValue(cpu, 'esp')
                count_addr = esp + 3*self.mem_utils.wordSize(cpu)
                self.top.writeWord(count_addr, count)
            else:
                self.top.writeRegValue('syscall_ret', count)
            #cpu.iface.int_register.write(reg_num, count)
            self.lgr.debug('dmod fullReplace %s in %s wrote %d bytes' % (self.fiddle.match, s, count))
            rm_this = True
            #SIM_break_simulation('deeedee')
        return rm_this

    def stopAlone(self, fiddle):
        self.stop_hap = self.top.RES_add_stop_callback(self.stopHap, fiddle)
        SIM_break_simulation('matchCmd')

    def matchCmd(self, s):
        ''' The match lets us stop looking regardless of whether or not the values are
            bad.  The "was" tells us a bad value, i.e., reason to run commands '''
        rm_this = None
        #self.lgr.debug('look for match of %s in %s' % (self.fiddle.match, s))
        if re.search(self.fiddle.match, s, re.M|re.I) is not None:
            #self.lgr.debug('found match of %s in %s' % (self.fiddle.match, s))
            rm_this = self.fiddle
            if re.search(self.fiddle.was, s, re.M|re.I) is not None:
                self.lgr.debug('found match in was of %s in %s' % (self.fiddle.was, s))
                SIM_run_alone(self.stopAlone, self.fiddle)
            #else:
            #    self.lgr.debug('did NOT found match in was of %s in %s' % (self.fiddle.was, s))
        return rm_this

    def checkString(self, cpu, addr, byte_array, count, tid=None, fd=None):
        ''' Modify content at the given addr if content meets the Dmod criteria '''
        retval = False
        if self.length is not None and count != self.length:
            self.lgr.debug('dmod checkString, length match fail byte array %s' % (str(byte_array)))
            return retval
        try:
            s = ''.join(map(chr,byte_array))
        except:
            self.lgr.debug('dMod checkString %d bytes failed join %s' % (len(byte_array), str(byte_array)))
            return retval
        self.lgr.debug('dMod checkString %d bytes (%d) in s: <%s>' % (len(byte_array), len(s), s))
        rm_this = False
        if self.kind == 'sub_replace':
            rm_this = self.subReplace(cpu, s, addr)
        elif self.kind == 'script_replace':
            rm_this = self.scriptReplace(cpu, s, addr, tid, fd)
        elif self.kind == 'full_replace':
            rm_this = self.fullReplace(cpu, s, addr)
        elif self.kind == 'match_cmd':
            rm_this = self.matchCmd(s)
        elif self.kind == 'open_replace':
           pass
        elif self.kind == 'syscall':
           pass
        else:
            print('Unknown kind %s' % self.kind)
            return
        if rm_this:
            self.count = self.count - 1
            self.lgr.debug('dmod checkString found match cell %s path %s count now %d' % (self.cell_name, self.path, self.count))
            retval = True
        return retval

    def stopHap(self, fiddle, one, exception, error_string):
        self.top.RES_delete_stop_hap(self.stop_hap)
        self.lgr.debug('dmod stop hap')
        for cmd in fiddle.cmds:
            self.lgr.debug('run command %s' % cmd)
            SIM_run_command(cmd)
    
    def getOperation(self):
        return self.operation    
   
    def getPath(self):
        return self.path 

    def getCount(self):
        return self.count

    def getComm(self):
        return self.comm

    def commMatch(self, comm):
        retval = False
        if len(self.comm) == 0:
            retval = True
        elif comm in self.comm:
            retval = True
        return retval

    def setOpen(self, fname, flags, tid):
        retval = None
        retval = self.fd_mgr.getFD(tid, self.path)
        flag_string = openFlags.getFlags(flags)
        if fname.startswith('/'):
            fname = fname[1:]
        else:
            self.lgr.error('dmod setOpen fname relative, cannot handle %s' % fname)
            return
        pathname = os.path.join(self.path_prefix, fname)
        if os.path.isfile(pathname):
            self.lgr.debug('dmod setOpen pathname %s exists' % pathname)
            use_path = pathname
            if 'TRUNC' in flag_string:
                try:
                    os.remove(pathname)
                except:
                    pass
        else:
            self.lgr.debug('dmod setOpen pathname %s does not exist, use parallel file system' % pathname)
            if self.fiddle.becomes.lower() == 'none':
                use_path = pathname
                os.makedirs(os.path.dirname(use_path), exist_ok=True)
            elif 'RD' in flag_string:
                use_path = self.fiddle.becomes
            elif 'DIRECTORY' in flag_string:
                os.makedirs(os.path.dirname(pathname), exist_ok=True)
                dir_fh = open(pathname, 'w')
                dir_fh.write('dumb_dir')
                dir_fh.close()
                use_path = pathname
            else:
                self.lgr.debug('dmod setOpen pathname mkdirs to parent %s' % (os.path.dirname(pathname)))
                os.makedirs(os.path.dirname(pathname), exist_ok=True)
                use_path = pathname

        self.lgr.debug('dmod setOpen pathname %s flags: %s' % (use_path, flag_string))
        pflags = ''
        if 'WRONLY' in flag_string:
            pflags = 'w'
        elif 'RDWR' in flag_string:
            pflags = 'r+'
        elif 'RDONLY' in flag_string:
            pflags = 'r'
        elif 'DIRECTORY' in flag_string:
            pflags = 'r'
        # TBD ??
        if len(pflags) == 0:
            os.makedirs(os.path.dirname(use_path), exist_ok=True)
            self.lgr.debug('dmod %s setOpen pathname %s nothing in flag string we recognize yet, force w' % (self.path, use_path))
            pflags = 'w'
        pflags = pflags+'b'
        key = '%s:%d' % (tid, retval)
        self.lgr.debug('dmod %s setOpen pathname %s pflags: %s key: %s' % (self.path, use_path, pflags, key))
        self.open_replace_fh[key] = open(use_path, pflags)
        self.open_replace_fname[key] = fname
        return retval

    def setFnameAddr(self, addr):
        self.fname_addr = addr
    
    def getMatch(self):                
        if self.fiddle is not None:
            return self.fiddle.match
        else:
            return None

    def getWas(self):                
        if self.fiddle is not None:
            return self.fiddle.was
        else:
            return None

    def getBecomes(self):                
        if self.fiddle is not None:
            return self.fiddle.becomes
        else:
            return None

    def readOpenReplace(self, tid, fd, count):
        key = '%s:%d' % (tid, fd) 
        if key not in self.primary.open_replace_fh:
            self.lgr.error('dmod readOpenReplace %s tid:%s fd: %d readOpenReplace key %s not in dictionary' % (self.path, tid, fd, key))
            return
        retval = self.primary.open_replace_fh[key].read(count)
        self.lgr.debug('dmod readOpenReplace read %d bytes %s' % (len(retval), str(retval)))
        return retval

    def writeOpenReplace(self, tid, fd, the_bytes):
        key = '%s:%d' % (tid, fd) 
        if key not in self.primary.open_replace_fh:
            self.lgr.error('dmod writeOpenReplace %s tid:%s fd: %d readOpenReplace not in dictionary' % (self.path, tid, fd))
            return
        if self.kind != 'open_replace':
            self.lgr.error('dmod writeOpenReplace dmod %s not a open_replace' % self.path)
            return 
        self.lgr.debug('dmod writeOpenReplace')
        retval = self.primary.open_replace_fh[key].write(bytes(the_bytes))
        self.primary.open_replace_fh[key].flush()
        self.lgr.debug('dmod writeOpenReplace wrote %d bytes to %s retval %d' % (len(the_bytes), self.primary.open_replace_fname[key], retval))
        return retval
        
    def resetOpen(self, tid, fd):
        if self.primary is not None:
            self.primary.resetOpen(tid, fd)
        else:
            self.lgr.debug('dmod resetOpen dmod %s' % self.path)
            self.fd_mgr.close(tid, fd, self.path)
            key = '%s:%d' % (tid, fd) 
            if key in self.open_replace_fh: 
                try:
                    self.open_replace_fh[key].close()
                    self.lgr.debug('dmod %s resetOpen did close on %s' % (self.path, self.open_replace_fname[key]))
                except:
                    pass
                del self.open_replace_fh[key]
                del self.open_replace_fname[key]
                self.lgr.debug('dmod %s resetOpen key %s removed' % (self.path, key))
            else:
                self.lgr.debug('dmod %s resetOpen key %s not in dict' % (self.path, key))

    def getCellName(self):
        return self.cell_name

    def toString(self):
        retval = 'path: %s comm: %s operation: %s' % (self.path, str(self.comm), self.operation)
        return retval

    def getBreak(self):
        return self.break_on_dmod
        
    def setCommCallback(self, op_set, call_params):
        self.lgr.debug('dmod %s setCommCallback opset %s' % (self.toString(), str(op_set)))
        self.op_set = op_set
        self.call_params = call_params

    def scheduled(self, tid):
        if self.op_set is not None:
            SIM_run_alone(self.scheduledAlone, tid)

    def scheduledAlone(self, tid):
        operation = self.getOperation()
        name = 'dmod-%s' % operation
        self.lgr.debug('dmod %s scheduled tid %s name %s' % (self.toString(), tid, name))
        self.top.runTo(self.op_set, self.call_params, ignore_running=True, run=False, name=name)
        self.op_set = None

    def rename(self, fname, fname2):
        if not fname.startswith('/') or not fname2.startswith('/'):
            self.lgr.error('dmod rename relative paths? %s %s' % (fname, fname2))
            return
        fname = fname[1:]
        fname2 = fname2[1:]
        path1 = os.path.join(self.path_prefix, fname)
        path2 = os.path.join(self.path_prefix, fname2)
        os.rename(path1, path2)
        self.lgr.debug('dmod rename %s to %s' % (path1, path2))

    def hasFDOpen(self, tid, fd):
        return self.fd_mgr.hasFDOpen(tid, fd, self.path)

    def dupFD(self, tid, old_fd, new_fd):
        self.fd_mgr.dupFD(tid, old_fd, new_fd, self.path)

    def getBytes(self):
        retval = None
        if self.bytes_file is not None:
            if os.path.isfile(self.bytes_file):
                with open(self.bytes_file, 'rb') as fh:
                    retval = fh.read()
            else:
                self.lgr.error('dmod failed to find bytes file %s' % self.bytes_file)
                self.top.quit()
        return retval

    def getSecondaryCount(self):
        self.secondary_count += 1
        retval = self.secondary_count
        return retval

if __name__ == '__main__':
    print('begin')
    d = Dmod('dog.dmod')
