#!/usr/bin/env python3
'''
Convert a RESim syscall trace file to include time stamps instead of cycle stamps
'''
import sys
tracefile = sys.argv[1]
with open(tracefile) as fh:
    time_start = None
    cycle_start = None
    sec_per_cycle = None
    for line in fh:
        line = line.strip()
        if len(line)==0:
            continue
        is_stamp = True
        cycle_stamp = line[:10]
        cycle = None
        try:
            cycle = int(cycle_stamp, 16)
        except:
            #print('not an hex %s' % cycle_stamp)
            is_stamp = False
        if is_stamp and not line[10:12] == '--':
            is_stamp = False
        if not is_stamp:
                print(line)
        else:
            if time_start is None and 'Trace start time' in line:
                timestr = line.split(':')[1]
                time_start = float(timestr)
                cycle_start = cycle
                print(line)
            elif sec_per_cycle is None and 'Clock frequency' in line:
                freqstr = line.split(':')[1]
                frequency = int(freqstr.split()[0])
                sec_per_cycle = 1/(frequency*1000000)
                print(line)
            elif sec_per_cycle is not None and cycle_start is not None and time_start is not None:
                time = time_start + (cycle - cycle_start) * sec_per_cycle
                #tstring = f'{time:07.4f}'
                tstring = '%012.7f' % time
                newline = tstring+line[10:]
                print(newline) 
            else:
                print('missing start cycle, time or frequency')
                exit(1)

        
