'''
Example of a ONE_DONE script that will be called by RESim after it has
been initialized.  This one calls injectIO with parameters
found in OS environment variables set by the script that repeatdedly 
starts RESim.
'''
import os
global mytop, myinject
def quit(cycles=None):
    global mytop, myinject
    print('in onedoneTrack quit')
    myinject.saveJson()
    mytop.quit(cycles)

def reportExit():
    path=os.getenv('ONE_DONE_PATH')
    print('%s caused exit, crashed')
    quit()

def onedone(top):
    global mytop, myinject
    mytop=top
    path=os.getenv('ONE_DONE_PATH')
    outpath=os.getenv('ONE_DONE_PARAM')
    only_thread_s=os.getenv('ONE_DONE_PARAM2')
    only_thread = False 
    if only_thread_s is not None and only_thread_s.lower() == 'true':
        only_thread = True

    no_page_faults_s=os.getenv('ONE_DONE_PARAM3')
    no_page_faults = False
    if no_page_faults_s is not None and no_page_faults_s.lower() == 'true':
        no_page_faults = True

    max_marks_s=os.getenv('ONE_DONE_PARAM4')
    max_marks = None 
    if max_marks_s is not None:
        max_marks = int(max_marks_s)
    fname=os.getenv('ONE_DONE_PARAM5')
    myinject = top.injectIO(path, save_json=outpath, callback=quit, go=False, only_thread=only_thread, no_page_faults=no_page_faults, max_marks=max_marks, fname=fname)
    myinject.setExitCallback(reportExit)
    myinject.go()


