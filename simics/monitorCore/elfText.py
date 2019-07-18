import os
import sys
import shlex
import subprocess
sys.path.append('/usr/local/lib/python2.7/dist-packages')
import magic
class Text():
    def __init__(self, address, offset, size):
        self.address = address
        self.offset = offset
        self.size = size
        self.locate = None

def getProgHdr(path):     
    ''' TBD: always use this since kernel does not use section info anyway? '''
    cmd = 'readelf -l %s' % path
    grep = 'grep " LOAD"'
    proc1 = subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc2 = subprocess.Popen(shlex.split(grep),stdin=proc1.stdout,
                         stdout=subprocess.PIPE,stderr=subprocess.PIPE)

    proc1.stdout.close() # Allow proc1 to receive a SIGPIPE if proc2 exits.
    out,err=proc2.communicate()
    print(out)
    addr = None
    size = 0
    for line in out.splitlines():
        parts = out.split()
        if addr is None:
            addr = int(parts[3], 16)
        size = int(parts[4], 16) + size
    return Text(addr, 0, size)

def getText(path, lgr):
    if not os.path.isfile(path):
        return None
    retval = None
    cmd = 'readelf -WS %s' % path
    grep = 'grep " .text"'
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
        if 'elf' in ftype.lower():
            lgr.debug('elfText getText, no sections, use program header')
            retval = text_segment = getProgHdr(path)
    else: 
        addr = int(parts[2], 16)
        offset = int(parts[3], 16)
        size = int(parts[4], 16)
        retval = Text(addr, offset, size)
    return retval

