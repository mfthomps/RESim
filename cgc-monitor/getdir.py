#!/usr/bin/env python
import sys
import os
import shutil
mondir= '/mnt/cgcsvn/cgc/trunk/cgc-monitor'
relative = sys.argv[1]
print('relative is %s' % relative)
target = os.path.join(mondir, relative)
text_base = os.path.join(target, '.svn', 'text-base')
flist = os.listdir(text_base)
try:
    os.makedirs(relative)
except:
    pass
for f in flist:
    noex =  os.path.splitext(f)[0]
    full = os.path.join(target, noex)
    dest = os.path.join(relative, f)
    if os.path.isfile(full):
        shutil.copy(full, os.path.join(relative,noex))
    else:
        print('no such file: %s' % full)

