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
        return None, None
    cmd = 'readelf -S %s' % path
    grep = 'grep " .text"'
    proc1 = subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE)
    proc2 = subprocess.Popen(shlex.split(grep),stdin=proc1.stdout,
                         stdout=subprocess.PIPE,stderr=subprocess.PIPE)

    proc1.stdout.close() # Allow proc1 to receive a SIGPIPE if proc2 exits.
    out,err=proc2.communicate()
     
    #print('out: {0}'.format(out))
    #print('err: {0}'.format(err))
    addr = int(out.split()[3], 16)
    offset = int(out.split()[4], 16)
    size = int(out.split()[5], 16)
    return Text(addr, offset, size)
     
