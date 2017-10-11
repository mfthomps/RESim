#!/usr/bin/python
import sys
import os
import glob
import getpass
os.umask(0000)
me=getpass.getuser()
pkg_dir = '/mnt/vmLib/bigstuff/cfe-challenges'
os.chdir(pkg_dir)
flist = glob.glob('*.deb')
#flist = os.listdir('./')
flist.sort(key=os.path.getmtime, reverse=True)

cs_list = open('cset_list.txt', 'w')
done_ids = []
for f in flist:
    #print f
    csid = f.split('_',1)[0]
    #print csid
    if csid in done_ids:
        ''' duplicate, delete the old file '''
        os.remove(f)
        print('removed old file %s' % f)
    else:
        done_ids.append(csid)
        cs_list.write(csid)
cs_list.close()

