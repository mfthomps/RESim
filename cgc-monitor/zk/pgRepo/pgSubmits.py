#!/usr/bin/python
import os
import sys
from monitorLibs import accessSQL
from monitorLibs import szk
from monitorLibs import utils
from monitorLibs import putMonitor
from monitorLibs import configMgr
from monitorLibs import updateMasterCfg
import shutil
import socket
from subprocess import Popen, PIPE
import cutils
'''
    Reference the cqe database to get competitor submissions
    Now uses the postgress db
'''

class pgSubmits():
    def __init__(self, no_replays, scoring_top, cfg, zk, lgr=None, best_polls=False):
        self.cfg = cfg
        self.lgr = lgr
        self.best_polls = best_polls
        if lgr is None:
            self.lgr = utils.getLogger('pgSubmits', self.cfg.logdir)
        self.lgr.debug("pgSubmits, scoring paths are relative to %s" % scoring_top) 
        # szk will overwrite cfg values using zk node
        self.zk = zk
        #  record the master configuration used in this run
        umc = updateMasterCfg.updateMasterCfg(self.zk, self.cfg, self.lgr)
        umc.updateAllMasterCfg()
        self.teams = []
        self.no_replays = no_replays
        self.scoring_top = scoring_top
        self.cbs_dir = self.cfg.cb_dir
        # the forensics instance of submissions
        self.sql = accessSQL.accessSQL(self.cfg.db_name, self.lgr)
        # instantiate a putMonitor to update the zookeeper node hierarchy
        self.pm = putMonitor.putMonitor(self.zk, self.cfg, self.lgr)
        os.umask(000)
        try:
            cbs = os.listdir(self.cbs_dir)
        except:
            self.lgr.error('error listing %s' % self.cbs_dir)
            print('error listing %s' % self.cbs_dir)
            exit(1)
        cbs.sort()
        for cb in cbs:
            self.sql.addCSI(cb)
        
   
    '''
        Put the given competitor submission into the forensics file system and zookeeper
    '''    
    def putSub(self, cs_id, competitor_id, serial, event_path, bins, pov):
        if competitor_id not in self.teams:
            self.teams.append(competitor_id)
            self.sql.addTeam(competitor_id)

        serial_string = utils.getSerialString(serial) 
        cb_name = cs_id+'_'+competitor_id+'_'+serial_string 
        #print('in pubSub for %s' % cb_name)
        cb_dir = self.cbs_dir+'/'+cs_id
        if not os.path.exists(os.path.dirname(cb_dir)):
            print 'could not find %s, exiting' % cb_dir
            self.lgr.error('could not find %s, exiting' % cb_dir)
            exit(1)
        cb_compet = cb_dir +'/'+ szk.COMPETITOR
        #print('make comp dir at %s' % cb_compet)
        cutils.safeMkDir(cb_compet)
        cb_this_competitor = cb_compet+'/'+competitor_id
        cb_cbs = cb_this_competitor + '/'+szk.CBs
        cutils.safeMkDir(cb_cbs)
        cb_povs = cb_this_competitor + '/'+szk.POVs
        cutils.safeMkDir(cb_povs)
        bin_path = cb_cbs+'/'+cb_name
        cutils.safeMkDir(bin_path)
        #print('make bin dir at %s' % bin_path)
        num_bins = utils.numBins(cs_id)
        if num_bins == len(bins):
            i = 1
            for b in bins:
                suffix = '_%02x' % i
                full = bin_path+'/'+cb_name+suffix
                #print('top: %s  file_path: %s' % (self.scoring_top, b.file_path))
                start_path = 0
                if b.file_path[0] == '/':
                    start_path = 1
                source = os.path.join(self.scoring_top, event_path, b.file_path[start_path:])
                self.lgr.debug('putSub bins would copy from %s to %s' % (source, full))
                # do not try to overwrite, maybe just resetting zk nodes
                # TBD use tmp file names for robustness
                if not os.path.exists(full):
                    #if self.cfg.fix_headers:
                    #    if self.fixHeaders(source, full) != 0:
                    #        print('bad cgc bin, copy anyway to avoid downstream failures')
                    #        shutil.copyfile(source, full)
                    #else:
                    shutil.copyfile(source, full)
                i += 1 
        else:
            print 'mismached number of bins for %s,  found %d expected %d' % (cb_name, len(bins), num_bins)                
            self.lgr.error('putSub mismached number of bins for %s,  found %d expected %d, skip this submit.' % (cb_name, len(bins), num_bins)) 
            return
        pov_name = None
        if pov is not None:
            pov_name = 'POV_'+cs_id+'_'+competitor_id+'_'+serial_string
            cutils.safeMkDir(cb_povs+'/'+pov_name)
            full = cb_povs+'/'+pov_name+'/'+pov_name+'.xml'
            start_path = 0
            if pov.file_path[0] == '/':
                start_path = 1
            source = os.path.join(self.scoring_top, event_path, pov.file_path[start_path:])
            # do not try to overwrite, maybe just resetting zk nodes
            # TBD use tmp file names for robustness
            self.lgr.debug('putSub pov would copy from %s to %s' % (source, full))
            if not os.path.exists(full):
                shutil.copyfile(source, full)
                f = open(full, 'r')
                pov = f.read()
                f.close()
                bad = '/usr/share/cgc-replay'
                if bad in pov: 
                    replaced = pov.replace('/usr/share/cgc-replay', '/usr/share/cgc-docs', 1)
                    self.lgr.debug('replaced bad dtd path ****************************')
                    self.lgr.debug('now : %s' % replaced[:90])
                    f = open(full, 'w')
                    f.write(replaced)
                    f.close()

        else:
            self.lgr.debug('no pov for %s' % cb_name)

        if not self.no_replays:
            polls = self.getCBPolls(cs_id)
            # this will add the team set to the teamSets module
            self.pm.updateTreeCompetitorCB(competitor_id, cb_name, serial, polls, pov_name)
            self.sql.addSet(competitor_id, cs_id, serial, cb_name, pov_name)
        else:
            self.pm.updateTreeCompetitorCB(competitor_id, cb_name, serial, None, None)

    def getCBPolls(self, common_name):
        retval = []
        if self.best_polls:
            retval = self.sql.bestPolls(common_name)
        else:
            a_poll_dir = '%s/%s/%s/%s' % (self.cfg.cb_dir, common_name, szk.AUTHOR, szk.POLLs)
            if os.path.isdir(a_poll_dir):
                author_polls = os.listdir(a_poll_dir)
                retval = author_polls[:2]
            else:
                self.lgr.debug('getCBPolls found no polls for '+common_name)
        return retval

    def fixHeaders(self, source, dest):
        ''' REMOVE, not used '''
        self.lgr.debug('fixHeaders for %s' % source)
        #retval = subprocess.call(['/mnt/cgc/zk/demoRepo/unstack', source, dest])
        p = Popen(['/usr/bin/unstack', source, dest], stdout=PIPE, stderr=PIPE)
        output, err = p.communicate()
        retval = p.returncode
        self.lgr.debug ('fixHeaders retval: %d output: %s  err: %s' % (retval, output, err))
        return retval


if __name__ == "__main__":
    print('testing?')
