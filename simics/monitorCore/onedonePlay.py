'''
Example of a ONE_DONE script that will be called by RESim after it has
been initialized.  This one calls playAFL
'''
import os
def onedone(top):
    protocol=os.getenv('ONE_DONE_PARAM')
    only_thread_s=os.getenv('ONE_DONE_PARAM2')
    program=os.getenv('ONE_DONE_PARAM3')
    target=os.getenv('ONE_DONE_PARAM4')
    targetFD=os.getenv('ONE_DONE_PARAM5')
    if targetFD is not None:
        if '0x' in targetFD:
            targetFD = int(targetFD, 16)
        else:
            targetFD = int(targetFD)
        
    count=os.getenv('ONE_DONE_PARAM6')
    no_page_faults_string=os.getenv('ONE_DONE_PARAM7')
    if no_page_faults_string.lower() == 'true':
        no_page_faults = True
    else:
        no_page_faults = False
    
    if count is not None:
        count = int(count)
    else:
        count = 1
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
            top.playAFL(base, parallel=True, only_thread=only_thread, fname=program, target=target, targetFD=targetFD, count=count, no_page_faults=no_page_faults)
