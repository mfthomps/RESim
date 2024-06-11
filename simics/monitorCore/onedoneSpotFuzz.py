'''
Example of a ONE_DONE script that will be called by RESim after it has
been initialized.  This one calls spotFuzz
'''
import os
import json
def onedone(top):
    address=int(os.getenv('ONE_DONE_PARAM'), 16)
    length=int(os.getenv('ONE_DONE_PARAM2'))
    breakpoint=int(os.getenv('ONE_DONE_PARAM3'), 16)
    fail_break_json=os.getenv('ONE_DONE_PARAM4')
    fail_break = json.loads(fail_break_json)
        
    here = os.getcwd()
    base = os.path.basename(here)
    if base.startswith('resim_'):
        base = os.path.basename(os.path.dirname(here))
    with open('logs/onedoneSpotFuzz.log', 'w') as fh:
        fh.write('in onedone of onedoneSpotFuzz\n') 
        fh.write('call spotFuzz target %s \n' % (base))
        top.spotFuzz(address, breakpoint, data_length=length, fail_break = fail_break)
