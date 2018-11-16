import os
import shlex
import subprocess
def getText(path):
    cmd = 'readelf -S %s' % path
    grep = 'grep " .text"'
    proc1 = subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE)
    proc2 = subprocess.Popen(shlex.split(grep),stdin=proc1.stdout,
                         stdout=subprocess.PIPE,stderr=subprocess.PIPE)

    proc1.stdout.close() # Allow proc1 to receive a SIGPIPE if proc2 exits.
    out,err=proc2.communicate()
     
    print('out: {0}'.format(out))
    print('err: {0}'.format(err))
    offset = out.split()[3]
    size = out.split()[4]
    return offset, size
     
