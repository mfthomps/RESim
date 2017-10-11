#!/usr/bin/env python
'''
Create a csv file of pov names by round and team
NOTE: hardcoded path to luigi/status/round directory.
'''
import os
import json
import sys
def usage():
    print('povsByRound.py') 

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
        pov_config = os.path.join(team_dir, str(team), 'pov', 'config.json')
        if os.path.isfile(pov_config):
            with open(pov_config) as json_fh:
                pov_json = json.load(json_fh)
                for pov_set in pov_json['povs']:
                    csid = pov_set['csid']
                    pov = os.path.basename(pov_set['pov_file'])
                    thrower = pov_set['team']
                    throws = pov_set['throws']
                    pov_type = pov_set['pov_type']
                    line = '%s,%s,%s,%s,%s,%s,%s' % (r, team, csid, thrower, throws, pov_type, pov)
                    print line                    

        else:
            #print('no file at %s' % df)
            pass
            
        
