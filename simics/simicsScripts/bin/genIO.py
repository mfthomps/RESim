#!/usr/bin/env python3
import sys
import os
import argparse
resim_dir=os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import resimUtils
import createNewIOFiles
import queueChecksums
def doForOneInput(input_path, cksum_dict, lgr):
    '''
    For each queue/watchmark pair derived from the input assocated with the given path
    '''
    queue_dir = os.path.join(input_path, 'queue')
    wm_dir = os.path.join(input_path, 'trackio')
    abs_queue_dir = os.path.realpath(queue_dir)
    abs_wm_dir = os.path.realpath(wm_dir)
    next_level_dir = os.path.join(input_path, 'next_level')
    os.makedirs(next_level_dir, exist_ok=True)
    flist = os.listdir(abs_queue_dir)
    for f in flist:
        qpath = os.path.join(abs_queue_dir, f)
        wpath = os.path.join(abs_wm_dir, f)
        f_no_ext = f.split('.', 1)[0]
        if not os.path.isfile(wpath):
            print('No watchmarks found at %s, bail' % wpath)
            break
        new_dir_name = os.path.join(next_level_dir, f_no_ext)
        out_parent = os.path.dirname(new_dir_name) 
        lgr.debug('Call create_new_iofiles  for %s, outputdir %s' % (qpath, new_dir_name))
        createNewIOFiles.create_new_iofiles(qpath, wpath, new_dir_name, out_parent, cksum_dict=cksum_dict)

def findTopLevel(from_level):
    '''
    Walk back up directories to find first level dir
    '''
    done = False
    cur_level = from_level
    while not done:
        parent = os.path.dirname(cur_level)
        p_parent = os.path.dirname(parent)
        if p_parent != 'next_level':
            break
        cur_level = p_parent
    return cur_level

def main():
    parser = argparse.ArgumentParser(prog='genIO.py', description='Generate new IO files for all queue/watchmarks pairs beneath a given level directory')
    parser.add_argument('level_dir', action='store', help='Path to the level directory.')
    args = parser.parse_args()
    lgr = resimUtils.getLogger('genIO', '/tmp', level=None)
    lgr.debug('Start of genIO.py')

    top_level = findTopLevel(args.level_dir)
    cksum_dict = {}
    dlist = os.listdir(top_level)
    for d in dlist:
        dpath = os.path.join(top_level, d)
        queueChecksums.checkThis(dpath, cksum_dict, stop_dir=args.level_dir)
    
    dlist = os.listdir(args.level_dir)
    for d in dlist:
        dpath = os.path.join(args.level_dir, d) 
        lgr.debug('Call doForOneInput for %s' % dpath)
        doForOneInput(dpath, cksum_dict, lgr)
 
if __name__ == '__main__':
    sys.exit(main())
