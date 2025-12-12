'''
Example of a ONE_DONE script that will be called by RESim after it has
been initialized.  This one calls injectIO with parameters
found in OS environment variables set by the script that repeatdedly 
starts RESim.
'''
import os
import json
from simics import *
global mytop, myinject
def quit(cycles=None):
    global mytop, myinject
    print('in onedoneTrack quit')
    myinject.saveJson(from_quit=True)
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
    target=os.getenv('ONE_DONE_PARAM5')
    trace_all_s=os.getenv('ONE_DONE_PARAM6')
    targetFD = None
    targetFD_s=os.getenv('ONE_DONE_PARAM7')
    if targetFD_s is not None:
        if '0x' in targetFD_s:
            targetFD = int(targetFD_s, 16)
        else:
            targetFD = int(targetFD_s)
    trace_all = False
    run = True
    trace = False
    trace_all = False
    if trace_all_s is not None and trace_all_s.lower() == 'true':
        trace_all = True
        run = False

    myinject = top.injectIO(path, save_json=outpath, callback=quit, go=False, only_thread=only_thread, no_page_faults=no_page_faults, 
                      max_marks=max_marks, target=target, targetFD=targetFD, trace=trace, trace_all=trace_all, run=run)
    top.setCommandCallback(quit)
    myinject.setExitCallback(reportExit)
    myinject.go()
    if trace_all:
        # determine how many cycles to run by adding backstop to final trackio cycle
        track_path = outpath.replace('trace', 'trackio')
        print('track path %s' % track_path) 
        track = json.load(open(track_path))
        mark_list = track['marks']
        sorted_marks = sorted(mark_list, key=lambda x: x['cycle'])
        last_mark_cycle = sorted_marks[-1]['cycle']
        print('last_mark_cycle 0x%x' % last_mark_cycle)
        first_mark_cycle = sorted_marks[0]['cycle']
        print('first_mark_cycle 0x%x' % first_mark_cycle)
        backstop_cycles =   9000000
        bsc = os.getenv('BACK_STOP_CYCLES')
        if bsc is not None:
            backstop_cycles = int(bsc)
        print('backstop cycles 0x%x' % backstop_cycles)
        now = top.getCPU().cycles
        now_delta = last_mark_cycle - now
        track_delta = last_mark_cycle - first_mark_cycle
        print('now 0x%x first delta 0x%x  now delta 0x%x' % (now, track_delta, now_delta))
        run_cycles = track_delta + backstop_cycles
        print('run 0x%x cycles' % run_cycles)
        top.autoMaze()
        SIM_continue(run_cycles)
        now = top.getCPU().cycles
        print('cycles when done 0x%x' % now)
        top.quit()


