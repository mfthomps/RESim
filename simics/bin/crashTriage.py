#!/usr/bin/env python3
'''
Parse the crash reports, skipping page boundary crashes.
'''
import os
cpath = '/tmp/crash_reports'
clist = os.listdir(cpath)
for crash in sorted(clist):
    if crash.endswith('.swp'):
        continue
    full = os.path.join(cpath, crash)
    page_boundary = False
    memcpy = None
    watch_addr = False
    add_to_zero = None
    prior_to_origin = False
    from_kernel = ''
    if os.path.getsize(full) == 0:
        continue
    with open(full) as fh:
        seg_addr = None
        show_line = ''
        for line in fh:
            if 'came from memcpy' in line:
                memcpy = line
                break
            elif 'boundary' in line:
                page_boundary = True
            elif line.startswith('SEGV'):
                seg_addr = line.strip().split()[5]
                if len(seg_addr) <= 4:
                    ''' look for something like [eax+0x12]'''
                    pass
            elif seg_addr is not None and line.startswith('Stack trace:'):
                watch_addr = True
            elif watch_addr:
                ''' First line of stack trace.  Does it contain +seg_addr?'''
                look_for = "+%s" % seg_addr
                if look_for in line:
                    add_to_zero = line
                watch_addr = False
                show_line = line.strip() + " SEGV: "+seg_addr
                #else:
                #    break
            elif add_to_zero is not None and 'occured prior to' in line:
                prior_to_origin = True
                break
            elif "START" in line:
                show_line = line
            elif "follows kernel write" in line:
                from_kernel = line
            elif "Perhaps a hang" in line:
                show_line = line
            
        if memcpy is not None:
            print('%s %s %s' % (crash, memcpy, from_kernel))
        elif page_boundary:
            print('%s page boundary, not memcpy' % crash)
        elif add_to_zero is not None:
            print('%s Add offset to zero, prior: %r 1st frame: %s' % (crash, prior_to_origin, add_to_zero))
        else:
            print('%s **OTHER** %s %s' % (crash, show_line, from_kernel)) 
