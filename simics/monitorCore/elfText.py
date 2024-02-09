import os
import sys
import shlex
import subprocess
sys.path.append('/usr/local/lib/python2.7/dist-packages')
sys.path.append('/usr/lib/python2.7/dist-packages')
sys.path.append('/usr/local/lib/python3.6/dist-packages')
sys.path.append('/usr/lib/python3/dist-packages')
import magic
class Text():
    def __init__(self, address, offset, size):
        self.text_start = address
        self.text_offset = offset
        self.text_size = size

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
    cmd = 'readelf -WS %s' % path
    #grep = 'grep " .text"'
    grep = 'grep " .plt"'
    proc1 = subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc2 = subprocess.Popen(shlex.split(grep),stdin=proc1.stdout,
                         stdout=subprocess.PIPE,stderr=subprocess.PIPE)

    proc1.stdout.close() # Allow proc1 to receive a SIGPIPE if proc2 exits.
    out,err=proc2.communicate()
     
    #print('out: {0}'.format(out))
    #print('err: {0}'.format(err))
    ''' section numbering has whitespace '''
    hack = out[7:]
    #print('readelf got %s from %s' % (hack, path))
    parts = hack.split()
    if len(parts) < 5:
        ftype = magic.from_file(path)
        if lgr is not None:
            if 'elf' in ftype.lower():
                lgr.debug('elfText getText, no sections return none')
            else:
                lgr.debug('elfText getText not elf at %s' % path)
    else: 
        addr = int(parts[2], 16)
        offset = int(parts[3], 16)
        size = int(parts[4], 16)
        retval = Text(addr, offset, size)
        #lgr.debug('elfText got start 0x%x offset 0x%x' % (addr, offset))
   
    return retval
