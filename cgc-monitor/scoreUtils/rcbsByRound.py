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
    team_dir = os.path.join(round_dir, str(r), 'team')
    team_list = os.listdir(team_dir)
    for team in sorted(team_list):
        rcb_config = os.path.join(team_dir, str(team), 'rcb', 'config.json')
        if os.path.isfile(rcb_config):
            with open(rcb_config) as json_fh:
                rcb_json = json.load(json_fh)
                for cset in rcb_json['challenge_sets']:
                    for rcb in sorted(cset['cbs']):
                        line = '%s,%s,%s,%s' % (r, team, cset['csid'], os.path.basename(rcb))
                        print line

        else:
            #print('no file at %s' % df)
            pass
            
        
