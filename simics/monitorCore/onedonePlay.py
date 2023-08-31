'''
Example of a ONE_DONE script that will be called by RESim after it has
been initialized.  This one calls playAFL
'''
import os
def onedone(top):
    protocol=os.getenv('ONE_DONE_PARAM')
    only_thread_s=os.getenv('ONE_DONE_PARAM2')
    program=os.getenv('ONE_DONE_PARAM3')
    only_thread = False 
    if only_thread_s is not None and only_thread_s.lower() == 'true':
        only_thread = True
    
    here = os.getcwd()
    base = os.path.basename(here)
    if base.startswith('resim_'):
        base = os.path.basename(os.path.dirname(here))
    with open('logs/onedonePlay.log', 'w') as fh:
        fh.write('in onedone of onedonePlay\n') 
        if protocol == 'tcp': 
            fh.write('call playAFLTCP target %s only_thread %r\n' % (base, only_thread))
            top.playAFLTCP(base, parallel=True, only_thread=only_thread, target=program)
        else:
            fh.write('call playAFL target %s only_thread %r\n' % (base, only_thread))
            top.playAFL(base, parallel=True, only_thread=only_thread, target=program)
