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
    #grep = 'grep -m1 " LOAD"'
    grep = 'grep " LOAD"'
    proc1 = subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc2 = subprocess.Popen(shlex.split(grep),stdin=proc1.stdout,
                         stdout=subprocess.PIPE,stderr=subprocess.PIPE)

    proc1.stdout.close() # Allow proc1 to receive a SIGPIPE if proc2 exits.
    out,err=proc2.communicate()
    #print(out)
    addr = None
    size = 0
    for line in out.splitlines():
        parts = line.split()
        #print('line was %s num parts is %d' % (line, len(parts)))
        if addr is None:
            addr = int(parts[2], 16)
        if len(parts) < 4:
            print('only %d parts in <%s>, fail' % (len(parts), line))
            return Text(0,0,0)

        try:
            size = int(parts[3], 16) + size
        except:
            print('bad parse of elf file %s expected int in %s' % (path, line))
            return Text(0,0,0)
    return Text(addr, 0, size)

def getText(path, lgr):
    if path is None or not os.path.isfile(path):
        return None
    retval = None
    ftype = magic.from_file(path)
    if 'elf' in ftype.lower():
        lgr.debug('elfText getText, just use program header')
        retval = text_segment = getProgHdr(path)
    else:
        lgr.debug('elfText getText not elf at %s' % path)
    return retval

def getRelocate(path, lgr):
    cmd = 'readelf -r %s' % path
    #lgr.debug('getRelocate %s' % path)
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
            #lgr.debug('getRelocate add entry for 0x%x' % addr)
            retval[addr] = parts[4]
        else:
            pass
            #lgr.debug('getRelocate not 5 %s' % line)
    return retval

def getTextNOTUSED(path, lgr):
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
    if True or len(parts) < 5:
        ftype = magic.from_file(path)
        if 'elf' in ftype.lower():
            lgr.debug('elfText getText, no sections, use program header')
            retval = text_segment = getProgHdr(path)
        else:
            lgr.debug('elfText getText not elf at %s' % path)
    else: 
        addr = int(parts[2], 16)
        offset = int(parts[3], 16)
        size = int(parts[4], 16)
        retval = Text(addr, offset, size)
    return retval
