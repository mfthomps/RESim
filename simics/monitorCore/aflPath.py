import os
import glob
def getAFLOutput():
    afl_dir = os.getenv('AFL_OUTPUT')
    if afl_dir is None:
        afl_dir = os.path.join(os.getenv('AFL_DATA'), 'output')
    else:
        print('Using AFL_OUTPUT from ini file, overrides bashrc')
    if afl_dir is None:
        print('No AFL_DATA or AFL_OUTPUT')
    return afl_dir

def getAFLPath(target, index, instance):
    retval = None
    afl_dir = getAFLOutput()
    if instance is None:
        glob_mask = '%s/%s/queue/id:*0%s,src*' % (afl_dir, target, index)
        glist = glob.glob(glob_mask)
        if len(glist) == 0:
            glob_mask = '%s/%s/queue/id:*0%s,sync*' % (afl_dir, target, index)
            glist = glob.glob(glob_mask)
    else:
        resim_instance = 'resim_%d' % instance
        glob_mask = '%s/%s/%s/queue/id:*0%s,src*' % (afl_dir, target, resim_instance, index)
        glist = glob.glob(glob_mask)
        if len(glist) == 0:
            print('No file at %s   -- try sync' % glob_mask)
            glob_mask = '%s/%s/%s/queue/id:*0%s,sync*' % (afl_dir, target, resim_instance, index)
            glist = glob.glob(glob_mask)
    if len(glist) == 0:
        print('No files found looking for %s' % glob_mask)
    elif len(glist) == 1:
        retval = glist[0]
    else:
        print('Too many matches, try adding leading zeros?')
    return retval
