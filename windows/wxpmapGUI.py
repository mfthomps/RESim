#!/usr/bin/env python3
import json
with open('win32k-per-syscall.json') as fh:
    call_map = {}
    myos = 'Windows XP'
    j = json.load(fh)
    for call_name in j:
        if myos in j[call_name]:
            for stuff in j[call_name][myos]:
                call = j[call_name][myos]['SP2']
                if call not in call_map:
                    call_map[call] = call_name
                    #print('%s  %d' % (call_name, call))
    #print('call 12 is %s' % call_map[12])
    cm = json.dumps(call_map)
    with open('winxpGUI.json', 'w') as fh:
        fh.write(cm)
