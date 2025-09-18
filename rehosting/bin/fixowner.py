#!/usr/bin/env python3
'''
Change ownership of files in a mounted root file system to match
ownership described in an ls -R output listing.
Must run as sudo
'''
import os
import sys
if len(sys.argv) != 3:
    print('fixowner.py path_to_root path_to_ls')
    exit(1)
user_map = {}
group_map = {}
path_to_root = sys.argv[1]
print('path to root %s' % path_to_root)
path_to_ls = sys.argv[2]
print('path to ls %s' % path_to_ls)
pw_path = os.path.join(path_to_root, 'etc/passwd')
with open(pw_path) as fh:
    for line in fh:
        if line.strip().startswith('#'):
            continue
        if ':' in line: 
            parts = line.split(':')
            user = parts[0]
            uid = parts[2]
            user_map[user] = uid 
group_path = os.path.join(path_to_root, 'etc/group')
with open(group_path) as fh:
    for line in fh:
        if line.strip().startswith('#'):
            continue
        if ':' in line: 
            parts = line.split(':')
            group = parts[0]
            gid = parts[2]
            group_map[group] = gid 

with open(path_to_ls) as fh:
    current_path = './'
    for line in fh:
        line = line.strip()
        if len(line) == 0:
            continue
        if line.endswith(':'):
            current_path = line[:-1]
        else:
            if current_path.startswith('./proc'):
                continue
            parts = line.split()
            user = parts[2]
            group = parts[3]
            file = parts[8]
            if file == '.' or file == '..':
                continue
            path = os.path.join(current_path, file)
            if user != 'root' or group != 'root':
                 if user not in user_map:
                     print('user %s not in user map for file %s' % (user, path))
                     continue
                 if group not in group_map:
                     print('groupuser %s not in groupuser map for file %s' % (group, path))
                     continue
                 uid = user_map[user]
                 gid = group_map[group]
                 #print('something not root: user: %s group: %s file: %s  would set owner to %s:%s' % (user, group, path, uid, gid))
                 full_path = os.path.join(path_to_root, path[2:])
                 if os.path.exists(full_path):
                     cmd = 'chown %s:%s %s' % (uid, gid, full_path)
                     print('cmd would be %s' % cmd)
                     os.system(cmd)
