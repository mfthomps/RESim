'''
Example of a ONE_DONE script that will be called by RESim after it has
been initialized.  This one calls AFL
'''
import os
def onedone(top):
    port=int(os.getenv('ONE_DONE_PARAM'))
    protocol=os.getenv('ONE_DONE_PARAM2')
    dead=os.getenv('ONE_DONE_PARAM3')
    fname=os.getenv('ONE_DONE_PARAM4')
    linear=os.getenv('ONE_DONE_PARAM5')
    is_linear = False
    with open('logs/oneDoneAFL.log', 'w') as fh:
        fh.write('in onedone of oneDoneAFL\n') 
        if linear is not None and linear.lower()=='true':
            is_linear=True
        if protocol == 'tcp': 
            fh.write('call aflTCP\n')
            top.aflTCP(port=port, dead=dead)
            fh.write('back from call aflTCP')
        else:
            fh.write('call afl\n')
            top.afl(port=port, fname=fname, linear=is_linear, dead=dead)
            fh.write('back from afl\n')

