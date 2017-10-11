#!/usr/bin/env python
'''
 * This software was created by United States Government employees
 * and may not be copyrighted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
'''

import json
import sys
import os

class schedule():
    def __init__(self):
        #schedule_file = './cgc/run/luigi/status/archive/config/schedule.json'
        schedule_file = '/etc/cgc-monitor/schedule.json'
        if not os.path.isfile(schedule_file):
            print('missing schedule file %s' % schedule_file)
            return
        
        with open(schedule_file) as fh:
            self.sched_json = json.load(fh)
        self.cb_map = {}
        self.rev_cb_map = {}
        with open('/etc/cgc-monitor/cbmap.txt') as fh:
            for line in fh:
                parts = line.strip().split()
                self.cb_map[parts[0]] = parts[1]
                self.rev_cb_map[parts[1]] = parts[0]

    def isIdInRound(self, csid, rnd):
        try:
            dum = int(common)
            common = self.rev_cb_map[csid]
        except:
            common = csid
        if common in self.sched_json[rnd]:
            return True
        else:
            return False

    def firstRound(self, csid):
        round_id = 1
        for round_sets in self.sched_json:
            #print('look for <%s> in %s' % (csid, str(round_sets)))
            if csid in round_sets:
                return round_id
            round_id += 1
        return None

if __name__ == "__main__":
    s = schedule()
    rnd = int(sys.argv[2])
    print('%r' % s.isIdInRound(sys.argv[1], rnd))

