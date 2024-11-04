'''
Example of a ONE_DONE script that will be called by RESim after it has
been initialized.  This one calls AFL
'''
import os
def onedone(top):
    port=int(os.getenv('ONE_DONE_PARAM'))
    #protocol=os.getenv('ONE_DONE_PARAM2')
    dead=os.getenv('ONE_DONE_PARAM3')
    fname=os.getenv('ONE_DONE_PARAM4')
    linear=os.getenv('ONE_DONE_PARAM5')
    target=os.getenv('ONE_DONE_PARAM6')
    targetFD=os.getenv('ONE_DONE_PARAM7')
    if targetFD is not None:
        if '0x' in targetFD:
            targetFD = int(targetFD, 16)
        else:
            targetFD = int(targetFD)
        
    count=os.getenv('ONE_DONE_PARAM8')
    if count is not None:
        count = int(count)
    else:
        count = 1
    is_linear = False
    with open('logs/oneDoneAFL.log', 'w') as fh:
        fh.write('in onedone of oneDoneAFL\n') 
        if linear is not None and linear.lower()=='true':
            is_linear=True
        #if protocol == 'tcp': 
        #    fh.write('call aflTCP\n')
        #    top.aflTCP(port=port, dead=dead)
        #    fh.write('back from call aflTCP')
        #else:
        fh.write('call afl\n')
        if targetFD is None:
            cmd = 'top.afl(port=%d, fname=%s, linear=%r, dead=%r, target=%s)' % (port, fname, is_linear, dead, target)
        else:
            cmd = 'top.afl(port=%d, fname=%s, linear=%r, dead=%r, target=%s, targetFD=0x%x, count=%d)' % (port, fname, is_linear, dead, target, targetFD, count)
        fh.write(cmd+'\n')
        fh.flush()
        top.afl(port=port, fname=fname, linear=is_linear, dead=dead, target=target, targetFD=targetFD, count=count)
        fh.write('back from afl\n')
        fh.flush()

