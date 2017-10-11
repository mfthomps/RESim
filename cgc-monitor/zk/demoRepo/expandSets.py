#!/usr/bin/python
'''
Expand packages from the cfe-cset-packages
Manually expand csids as new packages added and change
'''
import os
import glob
import shutil
os.umask(0000)
cset_path="/mnt/vmLib/bigstuff/challenge-sets"
cset_append='usr/share/cgc-challenges'
pkg_dir = '/mnt/vmLib/bigstuff/cfe-challenges'
try:
    os.mkdir(pkg_dir)
except:
    pass
os.chdir(pkg_dir)
print('make sure you are running on the nfs host')
raw_input("any key")
debs = os.listdir(pkg_dir)
for deb in debs:
    if deb.endswith('.deb'):
        print deb
        full_source = os.path.join(pkg_dir, deb)
        source_time = os.path.getctime(full_source)
        parts = deb.split('_')
        bits = parts[0].split('-')
        cb = bits[2].upper()+'_'+bits[3]
        full_dest = os.path.join(cset_path, cset_append, cb)
        dest_time = 0
        try:
            dest_time = os.path.getctime(full_dest)
        except:
            pass
        if source_time > dest_time:
            print('%s is newer' % full_source)
            try:
                shutil.rmtree(full_dest)
            except: 
                pass
            cmd = 'dpkg -x %s %s' % (full_source, cset_path)
            print cmd
            os.system(cmd)
            cmd = 'sudo chmod a+rx -R %s' % full_dest
            os.system(cmd)
