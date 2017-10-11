import subprocess
import shlex
def moduleSize(module):
    grep = 'grep "%s"' % module
    proc1 = subprocess.Popen(shlex.split('lsmod'),stdout=subprocess.PIPE)
    proc2 = subprocess.Popen(shlex.split(grep),stdin=proc1.stdout,
                         stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    
    proc1.stdout.close() # Allow proc1 to receive a SIGPIPE if proc2 exits.
    out,err=proc2.communicate()
    #print('out: {0}'.format(out))
    #print('err: {0}'.format(err))
    offset = out.split()
    return int(offset[1], 16)

