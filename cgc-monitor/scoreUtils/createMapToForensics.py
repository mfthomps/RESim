#!/usr/bin/env python
import json
import glob
import sys
import os
from monitorLibs import cfeCsetConfig
from monitorLibs import configMgr
cfg = configMgr.configMgr()
gname = sys.argv[1]
moved_dir = os.path.join(cfg.cfe_moved_dir, gname)
jfiles = glob.glob(moved_dir+'/*.json')
for f in jfiles:
    #print('f is %s' % f)
    cfile = os.path.join(moved_dir, f)
    #print('cfile is %s' % cfile)
    cset_cfg=cfeCsetConfig.cfeCsetConfig(cfile, cfg.db_name)
    pov_team = cset_cfg.getPovTeam()
    if pov_team is not None:
        team_id = cset_cfg.getTeamId()
        round_id = cset_cfg.getRoundId()
        common = cset_cfg.getCommonName()
        base = os.path.basename(f)
        print('%s,%d,%d,%d,%s' % (common, pov_team, team_id, round_id, base)) 
