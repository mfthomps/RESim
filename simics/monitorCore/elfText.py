#!/usr/bin/env python3
import os
import sys
import shlex
import subprocess
import resimUtils
class Text():
    def __init__(self, address, offset, size, plt_addr, plt_offset, plt_size, interp):
        self.text_start = address
        self.text_offset = offset
        self.text_size = size
        self.plt_addr = plt_addr
        self.plt_offset = plt_offset
        self.plt_size = plt_size
        self.interp = interp

    def toString(self):
        if self.text_start is not None:
            retval = 'addr: 0x%x offset 0x%x size 0x%x' % (self.text_start, self.text_offset, self.text_size)
        else:
            retval = 'addr: is None offset 0x%x size 0x%x' % (self.text_offset, self.text_size)
        return retval

def getRelocate(path, lgr, ida_funs):
    cmd = 'readelf -r %s -W' % path
    lgr.debug('getRelocate %s' % path)
    proc1 = subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = proc1.communicate()
    retval = {}
    for line in output[0].decode("utf-8").splitlines():
        parts = line.split()
        if len(parts) == 5:
            try:
                addr = int(parts[3], 16)
            except:
                #lgr.debug('getRelocate nothing from %s' % line)
                continue
            if addr == 0:
                addr = int(parts[0], 16)
            fun_name = parts[4]
            if fun_name.startswith('_'):
                fun_name = fun_name[1:]
                if '@' in fun_name:
                    fun_name = fun_name.split('@')[0]
            if ida_funs is not None:
                fun_name_dm = ida_funs.demangle(fun_name)
                retval[addr] = fun_name_dm
        else:
            pass
            #lgr.debug('getRelocate not 5 %s' % line)
    return retval

def getText(path, lgr):
    if path is None or not os.path.isfile(path):
        lgr.debug('elfText nothing at %s' % path)
        return None
    retval = None
    cmd = 'readelf -a --wide %s' % path
    #grep = 'grep " .text"'
    #grep = 'grep "-e .plt -e .text"'
    proc1 = subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #proc2 = subprocess.Popen(shlex.split(grep),stdin=proc1.stdout,
    #                     stdout=subprocess.PIPE,stderr=subprocess.PIPE)

    #proc1.stdout.close() # Allow proc1 to receive a SIGPIPE if proc2 exits.
    #out,err=proc2.communicate()
    out = proc1.communicate()
    addr = None
    offset = None
    size = None
    plt_addr = None
    plt_offset = None
    plt_size = None
    iself = False
    is_dyn = False
    is_aarch64 = False
    interp = None
 
    line_list = out[0].decode("utf-8").splitlines()
    line_iterator = iter(line_list) 
    for line in line_iterator:
        #lgr.debug(line)
        line = line.strip()
        if line.startswith('ELF Header'):
            iself = True
            continue
        if line.strip().startswith('Type:') and 'DYN' in line:
            is_dyn = True
            continue
        if line.strip().startswith('Machine:') and 'AArch64' in line:
            is_aarch64 = True
            continue
        if line.strip().startswith('Entry point'):
            parts = line.strip().split()
            if is_dyn:
                offset = int(parts[3], 16)
                lgr.debug('Entry point, setting offset to 0x%x' % offset)
            elif is_aarch64:
                addr = int(parts[3], 16)
            continue
        if '[Requesting program interpreter' in line:
            parts = line.strip().split()
            interp = parts[-1][:-1] 
        if line.startswith('LOAD') and not is_dyn and is_aarch64 and offset is None and ' E ' in line:
            parts = line.strip().split()
            offset = int(parts[2], 16)
            size = int(parts[3], 16)
            if lgr is not None:
                lgr.debug('readelf got LOAD offset 0x%x' % offset)
        elif line.startswith('LOAD') and is_dyn and is_aarch64 and ' E ' in line:
            # not quite, but better
            if size is None:
                size = 0
            parts = line.strip().split()
            addr_start = int(parts[2], 16)
            mem_size = int(parts[3], 16)
            size = addr_start + mem_size
            #lgr.debug('got size now 0x%x' % size)
        elif line.startswith('LOAD') and is_dyn and not is_aarch64 and ' E ' in line:
            lgr.debug('found load in line %s' % line)
            # not quite, but better
            if size is None:
                size = 0
            parts = line.strip().split()
            addr_start = int(parts[2], 16)
            mem_size = int(parts[3], 16)
            size = addr_start + mem_size
            lgr.debug('got size now 0x%x offset %s' % (size, str(offset)))
            if offset is None or offset == 0:
                offset = int(parts[2], 16)
                lgr.debug('got offset 0x%x' % offset)
            
        ''' section numbering has whitespace '''
        hack = line[4:]
        #if lgr is not None:
        #    lgr.debug('readelf got %s from %s' % (hack, path))
        
        parts = hack.split()
        if len(parts) < 5:
            pass
        else: 
            if parts[0].strip() == '.text':
                addr = int(parts[2], 16)
                offset = int(parts[3], 16)
                size = int(parts[4], 16)
            elif parts[0].strip() == '.plt':
                plt_addr = int(parts[2], 16)
                plt_offset = int(parts[3], 16)
                plt_size = int(parts[4], 16)
            else:
                pass
            #lgr.debug('elfText got start 0x%x offset 0x%x' % (addr, offset))
    if addr is not None or is_dyn or is_aarch64:
        retval = Text(addr, offset, size, plt_addr, plt_offset, plt_size, interp)
   
    return retval

if __name__ == '__main__':
    logname = 'elfText'
    logdir = '/tmp/'
    lgr = resimUtils.getLogger(logname, logdir)
    elf = getText(sys.argv[1], lgr=lgr)
    if elf is not None:
        print(elf.toString())
    else:
        print('Failed to find elf in %s' % sys.argv[1])

    sys.exit(0)
