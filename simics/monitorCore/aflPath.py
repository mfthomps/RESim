import os
import glob
import json
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


def getAFLCoveragePath(target, instance, index):
    resim_num = 'resim_%s' % instance
    afl_path = getAFLOutput()
    retval = None
    glob_mask = '%s/%s/%s/coverage/id:*%s,src*' % (afl_path, target, resim_num, index)
    glist = glob.glob(glob_mask)
    if len(glist) == 0:
        print('No file found for %s' % glob_mask)
    else:
        retval = glist[0]
    return retval

def getAFLCoverageList(target, get_all=False):
    glist = None
    afl_path = getAFLOutput()
    if not get_all:
        afl_dir = os.path.join(afl_path, target)
        unique_path = os.path.join(afl_dir, target+'.unique')
        if os.path.isfile(unique_path):
            ulist = json.load(open(unique_path))
            glist = []
            for path in ulist:
                glist.append(os.path.join(afl_dir, path)) 

    if glist is None:
        glob_mask = '%s/%s/resim_*/coverage/id:*,src*' % (afl_path, target)
        print('glob_mask is %s' % glob_mask)
        glist = glob.glob(glob_mask)
        if len(glist) == 0:
            ''' single instance '''
            glob_mask = '%s/%s/coverage/id:*,src*' % (afl_path, target)
            glist = glob.glob(glob_mask)
    return glist

def getTargetQueue(target, get_all=False):
    ''' get list of queue files, relative to afloutput.  ignore sync files and return based on target.unique if allowed.'''
    afl_list = []
    afl_output = getAFLOutput()
    afl_dir = os.path.join(afl_output, target)
    unique_path = os.path.join(afl_dir, target+'.unique')
    if not get_all and os.path.isfile(unique_path):
        cover_list = json.load(open(unique_path))
        for path in cover_list:
            full = os.path.join(afl_dir, path)
            base = os.path.basename(full)
            grand = os.path.dirname(os.path.dirname(full))
            new = os.path.join(grand, 'queue', base)
            afl_list.append(new)
        print('trackAFL found unique file at %s, %d entries' % (unique_path, len(afl_list)))
    else:
        if not get_all:
            print('No unique paths from %s, use all.' % unique_path)
        gpath = os.path.join(afl_dir, 'resim_*', 'queue', 'id:*')
        glist = glob.glob(gpath)
        if len(glist) > 0:
            #for path in sorted(glist):
            for path in glist:
                if 'sync:' not in path:
                    afl_list.append(path)
        else:
            qdir = os.path.join(afl_dir, 'queue')
            if os.path.isdir(qdir):
                afl_list = [f for f in os.listdir(qdir) if os.path.isfile(os.path.join(qdir, f))]
    return afl_list

def getTargetCrashes(target):
    afl_list = []
    afl_output = getAFLOutput()
    afl_dir = os.path.join(afl_output, target)
    cpath = os.path.join(afl_dir, 'resim_*', 'crashes', 'id:*')
    glist = glob.glob(cpath)
    if len(glist) > 0:
        #for path in sorted(glist):
        for path in glist:
            afl_list.append(path)
    else:
        cdir = os.path.join(afl_dir, 'crashes')
        if os.path.isdir(cdir):
            afl_list = [f for f in os.listdir(cdir) if os.path.isfile(os.path.join(cdir, f))]
    return afl_list

def getTargetPath(target):
    afl_output = getAFLOutput()
    target_path = os.path.join(afl_output, target)
    return target_path

def getRelativePath(f, target):
    afl_output = getAFLOutput()
    target_path = os.path.join(afl_output, target)
    retval = f[len(target_path)+1:]
    return retval
