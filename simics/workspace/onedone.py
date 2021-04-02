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
    report_index = int(index)
    top.crashReport(path, n=2, one_done=True, report_index=report_index)
