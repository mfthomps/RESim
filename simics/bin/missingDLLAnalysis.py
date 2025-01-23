#!/usr/bin/env python3
#
#
import sys
import os
import shutil
import shlex
import argparse
import subprocess
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import resimUtils
def doIdaDump(ini, prog, lgr=None):
    full = resimUtils.getFullPath(prog, ini, lgr=lgr)
    root_prefix = resimUtils.getIniTargetValue(ini, 'RESIM_ROOT_PREFIX', lgr=lgr)
    resim_image = os.getenv('RESIM_IMAGE')
    remove_prefix = os.path.join(resim_image, root_prefix)
    relative_path = full[len(remove_prefix)+1:]
    print('relative %s' % relative_path)
    cmd = 'idaDump.sh %s' % relative_path
    ssh_ps = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE,stderr=subprocess.PIPE, cwd=root_prefix)
    output = ssh_ps.communicate()
    for line in output[1].decode("utf-8").splitlines():
         print("error: "+line)
         ok = False
    for line in output[0].decode("utf-8").splitlines():
         print(line)

def checkMissingDLLs(ini, somap, lgr, root_prefix=None, generate=True):
    ''' return True if all found clib DLLs have analysis '''
    retval = False
    if not os.path.isfile(somap):
        print('Did not find somap %s' % somap)
        return retval
    with open(somap) as fh:
        retval = True
        for line in fh:
            lower = line.lower()
            if 'libc' in lower or 'qt5core' in lower or 'libstd' in lower or 'libgcc' in lower or 'msvcrt' in lower:
               fname = line.split(' ', 4)[4].strip()
               #print(fname)
               analysis = resimUtils.getAnalysisPath(ini, fname, lgr=lgr, root_prefix=root_prefix)
               if analysis is not None:
                   #print(analysis)
                   funs = analysis+'.funs'
                   if os.path.isfile(funs):
                       print('Found analysis at %s' % analysis)
                   else:
                       print('Missing analysis for %s, would be at %s' % (fname, analysis))
                       retval = False
               else:
                   print('Missing analysis for %s' % (fname))
                   retval = False
                   if generate:
                       doIdaDump(ini, fname, lgr=lgr)
    return retval
          

#def getFullPath(prog, ini, lgr=None):
def main():
    parser = argparse.ArgumentParser(prog='missingDLLAnalysis', description='Report on libc type DLLs in an SO map that lack analysis')
    parser.add_argument('ini', action='store', help='The ini file')
    parser.add_argument('somap', action='store', help='The so map file')
    args = parser.parse_args()
    lgr = resimUtils.getLogger('missingDLLAnalysis', './logs', level=None)
    checkMissingDLLs(args.ini, args.somap, lgr)

if __name__ == '__main__':
    sys.exit(main())
