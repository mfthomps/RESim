#!/usr/bin/env python
from monitorLibs import configMgr
from monitorLibs import szk
from monitorLibs import replayMgr
from monitorLibs import updateMasterCfg
from monitorLibs import utils
from monitorLibs import teamSets
import xml.etree.ElementTree as ET
try:
    import MySQLdb as mdb
except:
    import pymysql as mdb
import logging
import os
import fnmatch
import glob
import StringIO
'''
Enqueue all reference POVs against each RCB 
'''

class refVersusRCBs():
    def __init__(self):
        self.con = None
        self.cfg = configMgr.configMgr()
        self.zk = szk.szk(None, self.cfg)
        self.lgr = utils.getLogger('refVersusRCBs', '/tmp/')
        self.lgr.debug('begin')
        self.rpm = replayMgr.replayMgr(self.zk, self.cfg, self.lgr)
        self.team_sets = teamSets.teamSets(self.zk, self.lgr)
        master_cfg=szk.MASTER_CONFIG_NODE
        umc =  updateMasterCfg.updateMasterCfg(self.zk, self.cfg, self.lgr)
        self.checksum = umc.updateAllMasterCfg(master_cfg)
        try:
            self.con = mdb.connect('master', 'cgc', 'password')
        except mdb.Error, e:
            print("listDatabases, error %d: %s" % (e.args[0], e.args[1]))

    def isPOV(self, name):
        if self.cfg.cfe:
            if fnmatch.fnmatch(name,'*.pov') and \
               fnmatch.fnmatch(name,'POV_*'):
               return True
            else:
               return False
        else:
            if fnmatch.fnmatch(name,'*.xml') and \
               fnmatch.fnmatch(name,'POV_*'):
               return True
            else:
               return False
   
    def passedPolls(self, cb):
        cb_node = szk.CBS_NODE+'/'+cb
        children = self.zk.zk.get_children(cb_node)
        has_poll = False
        retval = True
        for replay in children:
            path = cb_node + '/' + replay
            if self.zk.isDone(path) and self.zk.isPoll(replay):
                has_poll = True
                entries, raw = self.zk.getLog(cb_node, replay)
                for entry in entries:
                    if len(entry['display_event'].strip()) > 0:
                        print('poll for %s fail: %s' % (cb, entry['display_event']))
                        retval = False 
        if not has_poll:
            retval = False
            print('no poll: %s' % cb)
        return retval

    def doCB(self, cb): 
        if not self.passedPolls(cb):
            print('failed polls: %s' % cb)
            return
        children = self.zk.zk.get_children(szk.CBS_NODE+'/'+cb)
        team_id = None
        for child in children:
            if child != 'config':
               team_set = self.rpm.getReplaySetName(cb, child) 
               if team_set.startswith('teamset'):
                   team_id = self.team_sets.getTeamId(team_set)
                   break
               else:
                   print('team set is %s' % team_set)
        if team_id is None:
            self.lgr.error('could not find team id for cb %s' % cb)
            print('could not find team id for cb %s' % cb)
            return
        self.lgr.debug('do cb for %s' % cb)
        parts = cb.split('-')
        csid = parts[1]
        csid_dir =  os.path.join(self.cfg.cb_dir, 'CB'+csid)+'*'
        dlist = glob.glob(csid_dir)
        if len(dlist) > 1:
            csid_dir = None
            for d in dlist:
                try:
                    tlist = os.listdir(os.path.join(self.cfg.cb_dir, d, 'author'))
                    csid_dir = d
                    break 
                except:
                    pass
            if csid_dir is None:
                print('cb %s, too many dirs %s' % (cb, str(dlist)))
                return
        elif len(dlist) == 0:
            print('no dirs for %s' % csid_dir)
            return 
        else:
            csid_dir = dlist[0]
        a_pov_dir = os.path.join(csid_dir, szk.AUTHOR, szk.POVs)
        if (os.path.isdir(a_pov_dir)):
            author_povs = os.listdir(a_pov_dir)
            for pov_d_name in author_povs:
                if self.cfg.cfe:
                    pov_f_name = pov_d_name+'.pov'
                else:
                    pov_f_name = pov_d_name+'.xml'
                self.lgr.debug('check author_povs: %s' % pov_f_name)
                if self.isPOV(pov_f_name):
                   pov = pov_f_name
                   self.lgr.debug('put pov for %s' % pov)
                   put_pov, got_nice = self.rpm.putReplay(cb, pov, False, szk.FORENSICS, self.checksum,
                                         set_name = team_id)
                  

    def eachCB(self):
        children = self.zk.zk.get_children(szk.CBS_NODE)
        children.sort()
        for child in children:
            self.doCB(child)

rvr = refVersusRCBs()
rvr.eachCB()
