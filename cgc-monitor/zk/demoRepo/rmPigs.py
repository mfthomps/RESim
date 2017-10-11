#!/usr/bin/env python
import sys
import os
with open('/tmp/CFE-pigs.txt') as fh:
    for l in fh:
        print l
        cmd = 'monitorUtils rmcb_any %s' % l.strip()
        os.system(cmd)
        print('done that')
