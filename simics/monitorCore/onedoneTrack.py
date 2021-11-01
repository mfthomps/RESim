'''
Example of a ONE_DONE script that will be called by RESim after it has
been initialized.  This one calls injectIO with parameters
found in OS environment variables set by the script that repeatdedly 
starts RESim.
'''
import os
global mytop, myinject
def quit():
    global mytop, myinject
    myinject.saveJson()
    mytop.quit()

def reportExit():
    path=os.getenv('ONE_DONE_PATH')
    print('%s caused exit, crashed')
    quit()

def onedone(top):
    global mytop, myinject
    mytop=top
    path=os.getenv('ONE_DONE_PATH')
    outpath=os.getenv('ONE_DONE_PARAM')
    myinject = top.injectIO(path, save_json=outpath, callback=quit, go=False)
    myinject.setExitCallback(reportExit)
    myinject.go()


