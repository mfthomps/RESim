#!/usr/bin/env python
import os
import sys
import glob
'''
Create crash reports for a given AFL target.
This is an example of a script the repeatedly starts
RESim (and thus Simics) to handle multi-udp crash
analysis.  
'''

''' target name, e.g., subdirectory of AFL output directory '''
target = sys.argv[1]
''' path to AFL output directory '''
afl_output = os.path.join(os.getenv('HOME'), 'SEED','afl','afl-output')
afl_dir = os.path.join(afl_output, target)
if not os.path.isdir(afl_dir):
   print('No afl directory found at %s' % afl_dir)
   exit

''' Get all crash files '''
crashes_dir = os.path.join(afl_dir, 'crashes*')
gmask = '%s/*' % crashes_dir
print("ReportCrash gmask: %s" % gmask)
glist = glob.glob(gmask)
flist=[]
for g in glist:
    if os.path.basename(g).startswith('id:'):
        flist.append(g)

''' The script to be called by RESim once it is initialized '''
os.environ['ONE_DONE_SCRIPT'] = 'onedone.py'

index=0
for f in flist:
    os.environ['ONE_DONE_PATH'] = f
    os.environ['ONE_DONE_PARAM'] = str(index)
    result = os.system('./monitor.sh high_alone')
    if result != 0:
        exit
    index += 1
print('done')
