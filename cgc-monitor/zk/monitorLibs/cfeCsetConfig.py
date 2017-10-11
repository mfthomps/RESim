#!/usr/bin/python
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
import json
import os
from monitorLibs import szk
from monitorLibs import configMgr
from monitorLibs import utils
'''
Decode & provide acccess methods for CFE configuration files
'''
class cfeCsetConfig():
    def __init__(self, json_file=None, game_id=None):
        self.set_cfg = None
        self.cfg = configMgr.configMgr()
        self.game_id = game_id
        #print('json is %s game is %s' % (json_file, game_id))
        if json_file is not None:
            self.loadFromFile(json_file)
        else:
            self.rcb_template = '{"team_id":0, "rcb":[], "ids":""}'
            self.pov_template = '{"team_id":0, "rcb":[], "ids":"", "pov":"", "pov_team":2, pov_config{}}'
    
    def loadFromFile(self, f):
        with open(f) as cfg_file: 
            data = cfg_file.read()
            data = data.replace("'", '"')
            #print data
            self.set_cfg = json.loads(data)

    def loadFromString(self, s):
        try:
            self.set_cfg = json.loads(s)
        except:
            print('unable to load jason from %s' % s)
            exit(1)

    def getRCBs(self):
        return sorted(self.set_cfg['rcb'])

    def getRCBNames(self):
        retval = []
        for rcb in self.set_cfg['rcb']:
            retval.append(os.path.basename(rcb))
        return sorted(retval)

    def getRCBRepo(self):
        compet_path = self.getCompetitorPath()
        retval = []
        rcb_id = sorted(self.set_cfg['rcb'])[0]
        base = os.path.basename(rcb_id)
        rcb_id, dum = os.path.splitext(base)
        rcb_id = utils.rmBinNumFromName(rcb_id)
        for rcb in self.set_cfg['rcb']:
            base = os.path.basename(rcb)
            retval.append(os.path.join(compet_path, szk.CBs, rcb_id, base))
        return sorted(retval)

    def getStr(self, s):
        retval = None
        if s in self.set_cfg:
            retval = self.set_cfg[s]
        return retval

    def getPovConfig(self):
        retval = None
        if 'pov_config' in self.set_cfg:
            retval = self.set_cfg['pov_config']
        return retval
        
    def getCBSeed(self, index=0):
        retval = None
        if 'pov_config' in self.set_cfg:
            pov_config = self.set_cfg['pov_config']
            retval = pov_config['cb_seeds'][0]
        return retval

    def getPovSeed(self, index=0):
        retval = None
        if 'pov_config' in self.set_cfg:
            pov_config = self.set_cfg['pov_config']
            retval = pov_config['pov_seeds'][0]
        return retval

    def getNegSeed(self, index=0):
        retval = None
        if 'pov_config' in self.set_cfg:
            pov_config = self.set_cfg['pov_config']
            retval = pov_config['negotiate_seeds'][0]
        return retval

    def getPov(self):
        return self.getStr('pov')

    def getIDS(self):
        return self.getStr('ids')

    def getIDSRepo(self):
        compet_path = self.getCompetitorPath()
        ids = self.getIDS()
        if ids is not None:
            base = os.path.basename(ids)
        else:
            print('cfeCsetConfig getIDSRepo, is is None in %s' % str(self.set_cfg))
            return None
        return os.path.join(compet_path, szk.IDSs, base)

    def getTeamId(self):
        return self.getStr('team_id')

    def getPovTeam(self):
        return self.getStr('pov_team')

    def getCommonName(self):
        '''
        derive common name from cfe-style rcb name.  If it has a second _, it is a multi bin.
        
        '''
        rcb_list = sorted(self.getRCBNames(), reverse=True)
        base = os.path.basename(rcb_list[0])
        cb_name = base.split('-')[1]
        if cb_name.count('_') == 2:
            ''' multi binary, assume last is count? '''
            parts = cb_name.split('_')
            suffix = parts[2]
            num_bins = '%02d' % int(suffix)
            common = 'CB'+parts[0]+'_'+parts[1]+num_bins 
        else:
            common = 'CB'+cb_name+'01'
        return common 

    def defineRCB(self, team, path):
        self.set_cfg = json.loads(self.rcb_template)
        self.set_cfg['rcb'].append(path)
        self.set_cfg['team_id'] = team

    def definePOV(self, team, paths, pov_team, pov, pov_cfg, ids):
        self.set_cfg = json.loads(self.pov_template)
        for path in paths:
            self.set_cfg['rcb'].append(path)
        self.set_cfg['team_id'] = team
        self.set_cfg['pov']=pov
        self.set_cfg['pov_config']=pov_cfg
        self.set_cfg['pov_team'] = pov_team
        self.set_cfg['ids']=ids

    def toString(self):
        if self.set_cfg is not None:
            return json.dumps(self.set_cfg)
        else:
            return None

    def toFile(self, path):
        if self.set_cfg is not None:
            f = open(path, 'w')
            f.write(self.toString())
            f.close()

    def getCompetitorPath(self):
        rcb_list = self.getRCBs()
        base = os.path.basename(rcb_list[0])
        num_bins = '%02d' % len(rcb_list)
        cb_name = base.split('-')[1]
        parts = cb_name.split('_')
        ''' get rid of tailing binary id '''
        cb_name = parts[0]+'_'+parts[1]
        #common = 'CB'+base[:11]+num_bins
        common = 'CB'+cb_name+num_bins
        #suffix = base[11:12]
        team = self.getTeamId()
        competitor_name = '%03d' % team
        cb_dir = self.cfg.cb_dir+'/'+common
        cb_compet = cb_dir +'/'+ szk.COMPETITOR
        cb_this_competitor = cb_compet+'/'+competitor_name
        return cb_this_competitor
    
    def getGameId(self):
        return self.game_id    

    def getRoundId(self):
        return self.getStr('round_id')

    def getPolls(self):
        return self.getStr('polls')

if __name__ == "__main__":
    f='/tmp/cfe.json'
    c = cfeCsetConfig()
    c.loadFromFile(f)
    rcbs = c.getRCBs()
    for rcb in rcbs:
        print rcb
    print c.getPov()
    print c.getIDS()
    print c.getTeamId()
    print c.getPovTeam()
    rcb = cfeCsetConfig()
    rcb.defineRCB(32, '/tmp/someRCB')
    print rcb.toString()
