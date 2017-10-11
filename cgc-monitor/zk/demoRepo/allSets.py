#!/usr/bin/python
import os
import glob
import shutil
path="127.0.0.1:8080/build-artifacts/challenges"
artifacts="http://"+path
#cmd = 'wget --no-proxy -r -l1 --no-parent -A.deb $artifacts'
#os.system(cmd)
#wget --no-proxy --no-directories -r -l1 --no-parent -A.deb $artifacts
#dirs = os.listdir(os.path.join('.',path))
#print dirs
t_dir = '/mnt/bigstuff/csets'
try:
    os.mkdir(t_dir)
except:
    pass
shutil.copyfile('./cqe-CSs-list.txt', '/mnt/bigstuff/csets/cqe-CSs-list.txt')
os.chdir(t_dir)
csids = {'CADET_00003', 'EAGLE_00005'}
with open('cqe-CSs-list.txt', 'r') as f:
    for cb in f:
        cmd = 'wget --no-proxy --no-directories -r -l1 --no-parent -A.deb '+artifacts+'/'+cb
        print cmd
        os.system(cmd)

