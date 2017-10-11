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
import sys

class cfeScores():
    def __init__(self):
        self.scores = {}
        with open('/etc/cgc-monitor/score_data.csv') as fh:
            for line in fh:
                common, thrower, defend, pov_type, round_id = line.split(',')
                thrower = int(thrower)
                defend = int(defend)
                if common not in self.scores:
                    self.scores[common] = {}
                if thrower not in self.scores[common]:
                    self.scores[common][thrower] = {}
                if defend not in self.scores[common][thrower]:
                    self.scores[common][thrower][defend] = []
                value = '%s:%s' % (round_id.strip(), pov_type.strip())
                self.scores[common][thrower][defend].append(value)

    def allCommon(self, common):
        for thrower in self.scores[common]:
            print thrower

    def didScore(self, common, thrower, defend, round_id):
            try:
                throwers = self.scores[common][int(thrower)]
            except:
                print('no thrower %s for %s' % (thrower, common))
                return None
            try:
                defends = throwers[int(defend)]
            except:
                print('no defends %s for thrower %s for %s' % (defend, thrower, common))
                return None
            values = defends
            for v in values:
                rnd, ptype = v.split(':')
                #print('rnd:%s look for %s' % (rnd, round_id))
                if int(rnd) == int(round_id):
                    return ptype
            return None

if __name__ == '__main__':
    cs = cfeScores()
    did = cs.didScore('CROMU_00055', 2, 1, 10)
    print('score? %r' % did)

#CROMU_00055,5,2,1,10

