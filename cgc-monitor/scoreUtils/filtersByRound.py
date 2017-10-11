#!/usr/bin/env python
'''
Create a csv file of filter names by round and team
NOTE: hardcoded path to luigi/status/round directory.
'''
import os
import json
import sys
def usage():
    print('filtersByRound.py') 

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
        ids_config = os.path.join(team_dir, str(team), 'ids', 'config.json')
        if os.path.isfile(ids_config):
            with open(ids_config) as json_fh:
                ids_json = json.load(json_fh)
                for cset in ids_json['challenges']:
                    cfg = ids_json['challenges'][cset]['config']
                    if 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' not in cfg:
                        #print str(cfg)
                        line = '%s,%s,%s,%s' % (r, team, cset, os.path.basename(cfg))
                        print line

        else:
            #print('no file at %s' % df)
            pass
            
        
