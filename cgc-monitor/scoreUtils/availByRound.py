#!/usr/bin/env python
'''
Create a csv file of rcb names by round and team
NOTE: hardcoded path to luigi/status/round directory.
'''
import os
import json
import sys
def usage():
    print('rcbsByRound.py') 

def getPOV(pov_set, seed):
    #print str(pov_set)
    #exit(1)
    for p in pov_set['povs']:
        if seed in p['cb_seeds']:
            return os.path.basename(p['pov_file'])
    return None

cb_map = {}
with open('cbmap.txt') as fh:
    for line in fh:
        parts = line.strip().split()
        cb_map[parts[0]] = parts[1]
csv = False
pov = False
just_first = False
round_dir = '/mftdata/cgc-archive/final/cgc/run/luigi/status/round'
round_list = os.listdir(round_dir)
for r in sorted(round_list):
    if r == '0':
        continue
    team_dir = os.path.join(round_dir, str(r), 'team')
    team_list = os.listdir(team_dir)
    for team in sorted(team_list):
        if team == '0':
            continue
        avail_dir = os.path.join(team_dir, str(team), 'score', 'availability')
        by_csid = os.listdir(avail_dir)
        for csid in by_csid:
                hash_id = csid.split('_')[1].split('.')[0]
                rcb_avail = os.path.join(avail_dir, csid)
                with open(rcb_avail) as json_fh:
                    for line in json_fh:
                        print('%s,%s,%s,%s' % (r, team, hash_id, line.strip()))

        else:
            #print('no file at %s' % df)
            pass
            
        
