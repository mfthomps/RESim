'''
Example of a ONE_DONE script that will be called by RESim after it has
been initialized.  This one calls crashReport with a path and an index
found in OS environment variables set by the script that repeatdedly 
starts RESim.
'''
import os
def onedone(top):
    path=os.getenv('ONE_DONE_PATH')
    index=os.getenv('ONE_DONE_PARAM')
    trackFD=None
    param2=os.getenv('ONE_DONE_PARAM2')
    if param2 is not None:
        trackFD = int(param2)
    report_index = int(index)
    top.crashReport(path, one_done=True, report_index=report_index, trackFD=trackFD)
