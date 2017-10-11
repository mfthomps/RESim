#!/usr/bin/python
import glob
import os
'''
Use getCFE_CSET_IDs.sh to get list of CFE CSETs, then confirm
that a debian packages for that CSET exists in the cfe-challenges
directory.  If a CSET fails jenkins build, it will be in svn,
but not in the artifacts.
'''
cpath='/mnt/vmLib/bigstuff/cfe-challenges/'
tfile='/tmp/tfile'
cmd='getCFE_CSET_IDs.sh >%s' % tfile
outfile='./allCFE-CSETS.txt'
os.system(cmd)
with open(outfile,'w') as out:
    with open(tfile) as full_list:
        for item in full_list:
            cb_name = item.strip()
            name = cb_name.lower().replace('_','-')
            match = glob.glob(cpath+'*%s*' % name)
            if len(match) == 0:
                print('%s not in %s' % (name, cpath))
            else: 
                out.write('%s\n' % cb_name)

print('latest list of CFE CSETs now in %s, please run ./dobuild & collectPackages, and then run fullCB on the NFS host' % outfile)
