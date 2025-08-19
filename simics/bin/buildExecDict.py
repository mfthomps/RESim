#!/usr/bin/env python3
#
# Build a dictionary of executable program paths and word sizes keyed by basename.
# First uses find to create an exec_list.txt file.  And then uses that to build the dictionary
# If multiple paths have the same base, each are printed and returned in a list.
# The dictionary is an optimization
# to avoid searching for windows paths that correspond to some comm that we find executing.
#
import os
import sys
import argparse
import json
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import resimUtils
import winProg
def buildExecDict(exec_list_file, ini, root_dir, lgr):
    exec_map = {}
    collisions = []
    if os.path.isfile(exec_list_file):
        with open(exec_list_file) as fh:
            for line in fh:
                if line.startswith('./'):
                    path = line[2:].strip()
                else:
                    path = line.strip()
                base = os.path.basename(path)
                #if base in exec_map:
                #    lgr.error('***** Collision on base %s, was %s new %s' % (base, exec_map[base]['path'], path))
                #    if base not in collisions:
                #        collisions.append(base)
                #    continue
                if base not in exec_map:
                    exec_map[base] = []
                full_path = os.path.join(root_dir, path)
                size, machine, image_base, addr_of_text = winProg.getSizeAndMachine(full_path, lgr)
                if machine is None:
                    print('Failed to find machine size for full path %s' % full_path)
                    continue
                if 'I386' in machine:
                    word_size = 4
                else:
                    word_size = 8
                entry = {}
                entry['path'] = path
                entry['base'] = base
                entry['word_size'] = word_size
                exec_map[base].append(entry)
        #for remove in collisions:
        #    del exec_map[remove]
        parent = os.path.dirname(exec_list_file)
        outfile = os.path.join(parent, 'exec_dict.json')
        exec_json = json.dumps(exec_map)
        with open(outfile, 'w') as fh:
            fh.write(exec_json)

    else:
        print('Failed to find exec file list file %s' % exec_file_list)

def buildList(root_dir, exec_list_file):
    if not os.path.isfile(exec_list_file):
        here = os.getcwd()
        os.chdir(root_dir)
        here = os.getcwd()
        print('dir is %s' % here)
        cmd = 'find ./ -name *.exe -type f | grep -v "/winsxs/" >%s ' % (exec_list_file)
        print('cmd is %s' % cmd)
        os.system(cmd)
        #cmd = 'find . -name *.dll | grep -vi windows | grep -vi microsoft | grep -v -i temp >>%s' % (exec_list_file)
        cmd = 'find . -name *.dll | grep -v -i temp | grep -v "winsxs/" >>%s' % (exec_list_file)
        print('cmd is %s' % cmd)
        os.system(cmd)
    else:
        print('Already exec list file at %s' % exec_list_file)

def main():
    parser = argparse.ArgumentParser(prog='buildExecDict', description='For each executable listed in a pre-created exec list, generate a dictionary entry reflecting the path to the executable and its word size.')
    lgr = resimUtils.getLogger('buildExecDict', '/tmp', level=None)
    parser.add_argument('ini', action='store', help='The RESim ini file.')
    args = parser.parse_args()
    root_dir = resimUtils.getIniTargetValue(args.ini, 'RESIM_ROOT_PREFIX')
    exec_list_file = resimUtils.getExecList(args.ini, lgr=lgr)
    buildList(root_dir, exec_list_file)
    buildExecDict(exec_list_file, args.ini, root_dir, lgr)
if __name__ == '__main__':
    sys.exit(main())
