#!/usr/bin/env python3
'''
Dump the windows 7 call parameters json, providing system call names
'''
import json
num_map = {}
call_map = json.load(open('win7.json'))
params = json.load(open('syscall_params.json'))
for call in params:
    call_name = call_map[call]
    print('%s  %s' % (call_name, call))
    for p in sorted(params[call]):
        print('\t%d' % p)
