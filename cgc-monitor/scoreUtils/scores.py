#!/usr/bin/env python
'''
Report on each successful POV.  Optionally create a comma separated list.
NOTE: hardcoded path to luigi/status/round below.
'''
import os
import json
import sys
def usage():
    print('scores.py [csv] | [pov] | [first]')
    print('\tcsv -- create a comma separated list')
    print('\tpov -- include id of POV that scored')
    print('\tfirst -- only include results from first throw')
    print('displays as: CSID thrower defender type round throw' )

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
if len(sys.argv) > 1:
    if sys.argv[1] == 'csv':
        csv = True
    elif sys.argv[1] == '-h':
        usage()
    elif sys.argv[1] == 'pov':
        pov = True
    elif sys.argv[1] == 'first':
        just_first = True
  
round_dir = '/mftdata/cgc-archive/final/cgc/run/luigi/status/round'
round_list = os.listdir(round_dir)
for r in sorted(round_list):
    team_dir = os.path.join(round_dir, str(r), 'team')
    team_list = os.listdir(team_dir)
    for team in sorted(team_list):
        df = os.path.join(team_dir, str(team), 'negotiation', 'parsed.json')
        if os.path.isfile(df):
            with open(df) as json_fh:
                neg_json = json.load(json_fh)
                for seed in sorted(neg_json):
                    #print('seed is %s' % seed)
                    throw = neg_json[seed]
                    #print(str(throw)) 
                    if 'result' in throw:
                        if throw['result'] == 'success' and (not just_first or throw['throw'] == 1):
                            pov_file = ""
                            if pov or csv:
                                pov_json_file = os.path.join(team_dir, str(team), 'pov', 'config.json')
                                #print('pov_json_file is %s' % pov_json_file)
                                with open(pov_json_file) as pov_fh:
                                    pov_json = json.load(pov_fh)
                                    pov_file = getPOV(pov_json, seed)
                            csid = throw['csid']
                            #print str(throw)
                            if csv:
                                print('%s,%s,%s,%s,%s,%s,%s' % (cb_map[csid], throw['team'], team, throw['pov_type'], r, throw['throw'], pov_file))
                            else:
                                print('%s pov_team: %s def_team: %s type: %s round: %s  throw: %s  %s' % (cb_map[csid], throw['team'], team, throw['pov_type'], r, throw['throw'], pov_file))
        else:
            #print('no file at %s' % df)
            pass
            
        
