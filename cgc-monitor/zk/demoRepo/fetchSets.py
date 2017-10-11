#!/usr/bin/python
'''
Get challenge sets from cgc-dev and install them into cset_path.
Superceeds getSets.py.  Will only retrieve packages newer than
the ones we currently have.
Uses getCFE_CSET_IDs.sh to find all CFE-style CSETs in svn
and then fetches latest versions of those.
'''
import os
import glob
import shutil
os.umask(0000)
path="127.0.0.1:8080/build-artifacts/challenges"
artifacts="http://"+path
cset_path="/mnt/vmLib/bigstuff/challenge-sets"
cset_append='usr/share/cgc-challenges'
pkg_dir = '/mnt/vmLib/bigstuff/cfe-challenges'
csids = []
#csids.append('KPRCA_00103')
tmp_file='/tmp/my_cfe_cb_list.txt'
cmd='getCFE_CSET_IDs.sh > %s' % tmp_file
os.system(cmd)
with open(tmp_file) as cfe_list:
    for cb_id in cfe_list:
        csids.append(cb_id)

try:
    os.mkdir(pkg_dir)
except:
    pass
os.chdir(pkg_dir)
#csids = ['NRFIN_00060','NRFIN_00062', 'NRFIN_00064']
#base='CROMU_000'
'''
base='KPRCA_000'
for num in range(91, 100):
    csid = base+'%d' % num
    csids.append(csid)
for num in range(55, 63):
    csid = base+'%d' % num
    csids.append(csid)
base='KPRCA_00'
for num in range(100, 103):
    csid = base+'%d' % num
    csids.append(csid)
base='NRFIN_000'
for num in range(61, 73):
    csid = base+'%d' % num
    csids.append(csid)
base='CROMU_000'
for num in range(60, 72):
    csid = base+'%d' % num
    csids.append(csid)

'''
for cb in csids:
    cmd = 'wget --no-proxy --no-directories --timestamping -r -l1 --no-parent -A.deb '+artifacts+'/'+cb
    print cmd
    os.system(cmd)
print("done fetching sets, now remove dups with sortLatestSets.py")

