'''
Example of a ONE_DONE script that will be called by RESim after it has
been initialized.  This one calls AFL
'''
import os
def onedone(top):
    protocol=os.getenv('ONE_DONE_PARAM')
    here = os.getcwd()
    base = os.path.basename(os.path.dirname(here))
    with open('logs/onedonePlay.log', 'w') as fh:
        fh.write('in onedone of onedonePlay\n') 
        if protocol == 'tcp': 
            fh.write('call playAFLTCP target %s\n' % base)
            top.playAFLTCP(base, parallel=True)
        else:
            fh.write('call playAFL target %s\n' % base)
            top.playAFL(base, parallel=True)
