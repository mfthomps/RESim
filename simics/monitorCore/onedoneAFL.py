'''
Example of a ONE_DONE script that will be called by RESim after it has
been initialized.  This one calls AFL
'''
import os
def onedone(top):
    port=int(os.getenv('ONE_DONE_PARAM'))
    protocol=os.getenv('ONE_DONE_PARAM2')
    dead=os.getenv('ONE_DONE_PARAM3')
    if protocol == 'tcp': 
        top.aflTCP(port=port)
    elif dead == 'TRUE':
        top.afl(port=port, dead=True)
    else:
        top.afl(port=port)
