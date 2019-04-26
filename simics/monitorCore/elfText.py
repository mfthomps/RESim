import os
import shlex
import subprocess
class Text():
    def __init__(self, start, offset, size):
        self.start = start
        self.offset = offset
        self.size = size

def getText(path):
    if not os.path.isfile(path):
        return None
    cmd = 'readelf -S %s' % path
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
        return Text(None, None, None)
    addr = int(parts[2], 16)
    offset = int(parts[3], 16)
    size = int(parts[4], 16)
    return Text(addr, offset, size)
     
