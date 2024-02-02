#!/usr/bin/env python3
#
# Utility example for updating kernel parameter files, either in snapshots or the param file itself.
# Run this from a workspace, providing either the snapshot and cell, or the name of the param file.
#
import os
import sys
import pickle
class DumbCPU():
    def __init__(self):
        self.architecture = 'x86'

resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import kParams

if len(sys.argv) == 3:
    snap = sys.argv[1]
    cellname = sys.argv[2]
    print('snap %s cell %s' % (snap, cellname))
    param_file = os.path.join('./', snap, cellname, 'param.pickle')
elif len(sys.argv) == 2:
    param_file = sys.argv[1]
else:
    print('fixParam.py [snapshot cellname] | [paramfile]')
the_params = None
if os.path.isfile(param_file):
    the_params = pickle.load(open(param_file, 'rb'))
else:
    print('No file found at %s' % param_file)
    exit(1)

cpu = DumbCPU()

base_param = kParams.Kparams(cpu, 8, None)

base_param.assignParams(the_params)
base_param.x86_reg_swap = True
base_param.printParams()
basename = os.path.basename(param_file)
outfile = '/tmp/%s' % basename
pickle.dump(base_param, open(outfile, 'wb'))
print('Param file pickle written to %s, copy it to %s if it looks right.' % (outfile, param_file))

