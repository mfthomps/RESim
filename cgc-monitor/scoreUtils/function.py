#!/usr/bin/env python
import os
import json
cb_map = {}
with open('cbmap.txt') as fh:
    for line in fh:
        parts = line.strip().split()
        cb_map[parts[0]] = parts[1]
round_dir = 'cgc/run/luigi/status/round'
round_list = os.listdir(round_dir)
for r in sorted(round_list):
    team_dir = os.path.join(round_dir, str(r), 'team')
    team_list = os.listdir(team_dir)
    for team in sorted(team_list):
        fb = os.path.join(team_dir, str(team), 'poll', 'feedback.json')
        if os.path.isfile(fb):
            with open(fb) as json_fh:
                feedback_json = json.load(json_fh)
                for results in sorted(feedback_json['poll']):
                      success = results['functionality']['success']
                      if success != 100:
                          #print('team %s %s %d' % (team, results['csid'], success))
                          print('%s, %s, %s, %d' % (results['csid'], r, team, success))
