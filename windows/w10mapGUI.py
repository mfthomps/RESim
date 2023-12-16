#!/usr/bin/env python3
import json
with open('win32k-per-syscall.json') as fh:
    call_map = {}
    myos = 'Windows 10'
    j = json.load(fh)
    for call_name in j:
        if myos in j[call_name]:
            for stuff in j[call_name][myos]:
                if '1809' in j[call_name][myos]:
                    call = j[call_name][myos]["1809"]
                    if call not in call_map:
                        call_map[call] = call_name
                        #print('%s  %d' % (call_name, call))
    #print('call 12 is %s' % call_map[12])
    cm = json.dumps(call_map)
    with open('win10GUI.json', 'w') as fh:
        fh.write(cm)
