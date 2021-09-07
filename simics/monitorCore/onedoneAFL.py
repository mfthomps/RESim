'''
Example of a ONE_DONE script that will be called by RESim after it has
been initialized.  This one calls AFL
'''
import os
def onedone(top):
    path=os.getenv('ONE_DONE_PATH')
    port=int(os.getenv('ONE_DONE_PARAM'))
    top.afl(port=port)
