#!/usr/bin/env python
import os
import sys
import json

class ghostScores():
    class ghost():
        def __init__(self, round_id, thrower, pov, rcb_list):
            self.round_id = int(round_id)
            self.thrower = thrower
            self.pov = pov
            self.rcb_list = rcb_list
        def toString(self):
            print('round: %d thrower: %s pov: %s rcb: %s' % (self.round_id, self.thrower, self.pov, self.rcb_list[0]))

    def __init__(self,  fname):
        json_path = '/mnt/vmLib/bigstuff/cfe-games/cfe_moved/1470326433.800818'

        self.scores={}
        with open(fname) as fh:
            for line in fh:
                parts = line.split()
                if parts[2] != 'def:3':
                    continue
                csid = parts[0].strip()
                thrower = parts[1].split(':')[1]
                if csid not in self.scores:
                    #print('new csid %s' % csid)
                    self.scores[csid] = []
                #print('add %s %s %s ' % (csid, parts[3], thrower)) 
                fname = os.path.join(json_path, parts[4])
                pov = None
                with open(fname) as data_file:
                    forensics = json.load(data_file) 
                    pov = os.path.basename(forensics['pov'])
                    j_rcb_list = forensics['rcb']
                    rcb_list = []
                    for rcb in j_rcb_list:
                        rcb_list.append(os.path.basename(rcb)) 
                g = self.ghost(parts[3], thrower, pov, rcb_list)
                self.scores[csid].append(g)
        '''
        for csid in self.scores:
            print('<%s>' % csid)
            for s in self.scores[csid]:
                s.toString()
        '''

    class povPair():
        def __init__(self, thrower, pov_file):
            self.thrower = int(thrower)
            self.pov_file = pov_file

    def getHoneyPOVs(self, csid, rcb_list):
        retval = [] 
        if csid in self.scores:
            for s in self.scores[csid]:
                #print('round %d look for povs in %s for  %s compare ghost %s' % (round_id, csid, str(rcb_list), s.rcb_list[0]))
                #print('%s %s' % (s.rcb_list[0], rcb_list[0]))
                if s.rcb_list[0] in rcb_list:
                    #print('getHoneyPOVs add %s %s' % (s.thrower, s.pov))
                    pair = self.povPair(s.thrower, s.pov)
                    retval.append(pair)
       
        else:
            pass
            #print('csid <%s> not in scores' % csid)
        return retval

    def printScores(self, tag, csid, min_round, next_round):
        
        if csid in self.scores:
            #print('look for rounds %d %d for <%s>' % (min_round, next_round, csid))
            prev_round = 0
            for s in self.scores[csid]:
                #s.toString()
                #print('********round id  %d ' % (s.round_id))
                if s.round_id >= min_round and s.round_id < next_round:
                    if s.round_id != prev_round:
                        print('\t  round %2d  team %s scored on honeypot *******' % (s.round_id, s.thrower))
                    prev_round = s.round_id
       
        else:
            pass
            #print('csid <%s> not in scores' % csid)

if __name__ == "__main__":
    fname = 'ghost_scores.txt'
    dum = ghostScores(fname)

    print('KPRCA_00102, 88, 99') 
    dum.printScores(' ','CROMU_00065', 6, 9) 
