#!/usr/bin/python
'''
Get challenge sets from cgc-dev and install them into cset_path.
Superceeds getSets.py.  Will only retrieve packages newer than
the ones we currently have.
'''
import os
import sys
os.umask(0000)
path="127.0.0.1:8080/build-artifacts/challenges"
artifacts="http://"+path
cset_path="/mnt/vmLib/bigstuff/challenge-sets"
cset_append='usr/share/cgc-challenges'
pkg_dir = '/mnt/vmLib/bigstuff/cfe-challenges'
csids = []
try:
    os.mkdir(pkg_dir)
except:
    pass
os.chdir(pkg_dir)
cmd = 'wget --no-proxy --no-directories --timestamping -r -l1 --no-parent -A.deb '+artifacts+'/'+sys.argv[1]
print cmd
#os.system(cmd)
print("done fetching sets, now remove dups with sortLatestSets.py")

