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
import szk
import replayMgr
import utils
import time
import os
import sys
import kazoo
import fnmatch
import socket
import logging
import teamSets
import updateMasterCfg
import accessSQL
'''
    Update a zookeeper tree to reflect the CBs, PoVs and Polls found in a CGC item directory.
    See the 027-item-naming-cqe.txt RFC for details of the structures.
    An effect of this function is to create configuration nodes reflecting program sections.
    This program is expected to run on a host having file system access to the entire CB
    hierarchy.  TBD: revise per CB/Poll/PoV repository
'''
class putMonitor():
    def __init__(self, zk, cfg, lgr, master_cfg=szk.MASTER_CONFIG_NODE, need_sql = False):
        self.lgr = lgr
        self.zk = zk
        self.cfg = cfg
        self.team_sets = teamSets.teamSets(self.zk, lgr=self.lgr) 
        self.rpm = replayMgr.replayMgr(zk, cfg, self.lgr)
        self.sql = None
        ''' only for sets that were already vetted '''
        self.done_path = os.path.join(cfg.cfe_done_files_dir, cfg.cgc_event)
        umc =  updateMasterCfg.updateMasterCfg(zk, cfg, self.lgr)
        self.checksum = umc.updateAllMasterCfg(master_cfg)
        if self.checksum is None:
            self.lgr.debug('putMonitor init, given config missing, revert to master.cfg')
            print('putMonitor init, given config missing, revert to master.cfg')
            self.checksum = umc.updateAllMasterCfg(szk.MASTER_CONFIG_NODE)
        else:
            self.lgr.debug('putMonitor, init, updated all master config nodes, run with config: "%s", checksum: %s' % (master_cfg, self.checksum))
            print('putMonitor, init, updated all master config nodes, run with config: "%s", checksum: %s' % (master_cfg, self.checksum))

        ''' POVs are vetting using an alternate config, e.g., the tracks syscalls '''
        pov_cfg = None
        self.pov_checksum = None
        try:
            pov_cfg = self.cfg.pov_cfg
        except:
            self.lgr.debug('putMonitor, init, no pov_cfg in configMgr')
        if pov_cfg is not None:
            pov_node, dum = zk.nodeFromConfigName(pov_cfg)
            self.pov_checksum = umc.getChecksum(pov_node)
            self.lgr.debug('putMonitor, init, pov_cfg is %s node: %s checksum %s' % (pov_cfg, pov_node, self.pov_checksum))
        if need_sql:
            self.sql = accessSQL.accessSQL(self.cfg.db_name, self.lgr)
            self.lgr.debug('putMonitor connected to db %s' % self.cfg.db_name)

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

    def isPoll(self, name):
        if fnmatch.fnmatch(name,'*.xml') and \
           fnmatch.fnmatch(name,'SP_*'):
           return True
        else:
           return False

    def createCBNode(self, cb_path, cb):
        try:
            self.zk.zk.create(cb_path, '', None, False, False, True) 
            print 'createCBNode write configuruation node info for cb %s path %s' % (cb, cb_path)
            self.lgr.debug("createCBNode cb configuration file at %s for cb %s" % (cb_path, cb))
            self.rpm.multiBinaryCB(cb_path, cb)
        except kazoo.exceptions.NodeExistsError:
            print 'createCBNode already had node for cb %s path %s, try updating program sections anyway' % (cb, cb_path)
            self.rpm.multiBinaryCB(cb_path, cb)
            pass

    def updateTreeCBs(self, queue_name):
        cbs = os.listdir(self.cfg.cb_dir)
        cbs.sort()
        for cb in cbs:
            cb_path = szk.CBS_NODE+"/"+cb
            self.createCBNode(cb_path, cb)
            # get author's mitigated CB if any
            a_mg_path = '%s/%s/%s/%s' % (self.cfg.cb_dir, cb, szk.AUTHOR, cb+'_'+szk.MG)
            self.lgr.debug( 'cb is %s' % cb)
            self.lgr.debug( 'a_mg_path is %s' % a_mg_path)
            cb_mg = None
            if os.path.isdir(a_mg_path):
                print 'GOT A MG '+a_mg_path
                cb_mg = cb+'_'+szk.MG
                cb_path = szk.CBS_NODE+"/"+cb_mg
                self.createCBNode(cb_path, cb_mg)

            cmp_dir = '%s/%s/%s' % (self.cfg.cb_dir, cb, szk.COMPETITOR)
            if os.path.isdir(cmp_dir):
                #print('found dir at %s' % cmp_dir)
                cmps = os.listdir(cmp_dir)
                for competitor in cmps:
                    c_cb_dir = cmp_dir+'/%s/%s' % (competitor, szk.CBs)
                    #print('look for c_cb_dir %s' % c_cb_dir)
                    if os.path.isdir(c_cb_dir):
                        # do CBs generated by this competitor
                        competitor_cbs = os.listdir(c_cb_dir)
                        #if len(competitor_cbs) > 1:
                        #   print 'more than one mitigated cb for competitor at %s' % c_cb_dir
                        #   exit(1)
                        for cb_f_name in competitor_cbs:
                            should_be = cb+'_'+competitor
                            if not cb_f_name.startswith(should_be):
                                print 'updateTree CBs unexpected cb name in %s: %s' % (c_cb_dir, cb_f_name)
                                if not self.cfg.cfe:
                                    exit(1)
                                else:
                                    continue

                            cb_path = szk.CBS_NODE+"/"+cb_f_name
                            try:
                               self.zk.zk.create(cb_path, '', None, 
                                        False, False, False) 
                            except kazoo.exceptions.NodeExistsError:
                               print('putMonitor already exists %s' % cb_path)

                            self.lgr.debug("putMonitor create cb configuration file at %s for cb %s" % (cb_path, cb_f_name))
                            print("putMonitor create cb configuration file at %s for cb %s" % (cb_path, cb_f_name))
                            self.rpm.multiBinaryCB(cb_path, cb_f_name)
            else:
                print('no dir at %s' % cmp_dir)

    def oneReplay(self, cb, replay, queue_name):
        put_replay, got_nice = self.rpm.putReplay(cb, replay, False, queue_name, self.checksum)
        if not put_replay:
            print('failed to put replay %s %s' % (cb, replay))


    def oneCB(self, cb, be_nice, queue_name, just_vuln=False, all_polls=False, just_polls=False, just_povs=False, max_sessions=None):
        print 'updateTree for %s' % cb
        self.lgr.debug('updateTree for %s' % cb)
        got_cb_lock = False
        got_mg_lock = False
        cb_sleep = 0
        pov_sleep = 0
        session_count = 0
        time.sleep(cb_sleep)
        # get author's mitigated CB if any
        a_mg_path = '%s/%s/%s/%s' % (self.cfg.cb_dir, cb, szk.AUTHOR, cb+'_'+szk.MG)
        self.lgr.debug( 'cb is %s' % cb)
        self.lgr.debug( 'a_mg_path is %s' % a_mg_path)
        cb_mg = None
        if not just_vuln and os.path.isdir(a_mg_path):
            print 'GOT A MG '+a_mg_path
            cb_mg = cb+'_'+szk.MG

        # get povs generated by the CB author
        a_pov_dir = '%s/%s/%s/%s' % (self.cfg.cb_dir, cb, szk.AUTHOR, szk.POVs)
        if (not just_vuln and os.path.isdir(a_pov_dir)) and not just_polls:
            author_povs = os.listdir(a_pov_dir)
            for pov_d_name in author_povs:
                if self.cfg.cfe:
                    pov_f_name = pov_d_name+'.pov'
                else:
                    pov_f_name = pov_d_name+'.xml'
                self.lgr.debug('check author_povs: %s' % pov_f_name)
                if self.isPOV(pov_f_name):
                   time.sleep(pov_sleep)
                   #pov = pov_f_name[:len(pov_f_name)-4]
                   ''' pov in zk now includes the extension .pov '''
                   pov = pov_f_name
                   self.lgr.debug('put pov for %s' % pov)
                   put_pov, got_nice = self.rpm.putReplay(cb, pov, be_nice, queue_name, self.checksum)
                   if put_pov:
                       session_count = session_count + 1
                       got_cb_lock = got_cb_lock or got_nice
                   if cb_mg is not None:
                       put_pov, got_nice = self.rpm.putReplay(cb_mg, pov, be_nice, queue_name, self.checksum)
                       if put_pov:
                           session_count = session_count + 1
                           got_mg_lock = got_mg_lock or got_nice
                if max_sessions is not None and session_count >= max_sessions:
                    print('reached max sessions %d' % max_sessions)
                    return session_count
        else:
            print 'no author pov files for %s' % a_pov_dir
        if not just_povs:
            # get polls generated by the CB author
            a_poll_dir = '%s/%s/%s/%s' % (self.cfg.cb_dir, cb, szk.AUTHOR, szk.POLLs)
            if os.path.isdir(a_poll_dir):
                if just_vuln or all_polls:
                    # use all polls
                    author_polls = os.listdir(a_poll_dir)
                else:
                    # get best coverage polls from db, if none,just get first two from directory
                    #author_polls = sql.bestPolls(cb, cc_con=cc_con)
                    #if len(author_polls) == 0:
                    author_polls = os.listdir(a_poll_dir)[:2]
                for poll_d_name in author_polls:
                    poll_f_name = poll_d_name+'.xml'
                    if self.isPoll(poll_f_name):
                       time.sleep(pov_sleep)
                       poll = poll_f_name[:len(poll_f_name)-4]
                       put_poll, got_nice = self.rpm.putReplay(cb, poll, be_nice, queue_name, self.checksum)
                       if put_poll:
                           session_count = session_count + 1
                           got_cb_lock = got_cb_lock or got_nice
                       if cb_mg is not None:
                           put_poll, got_nice = self.rpm.putReplay(cb_mg, poll, be_nice, queue_name, self.checksum)
                           if put_poll:
                               session_count = session_count + 1
                               got_mg_lock = got_mg_lock or got_nice
                    if max_sessions is not None and session_count >= max_sessions:
                        print('reached max sessions %d' % max_sessions)
                        return session_count
            else:
                print 'no author poll files for %s' % a_poll_dir
   
        # get mitigated CBs and povs generated by competitors 
        if not just_vuln:
            got_cb_lock, got_mg_lock, session_count = self.doCompetitors(cb, cb_mg, pov_sleep, 
                    be_nice, queue_name, got_cb_lock, got_mg_lock, session_count, just_povs)
        if got_cb_lock:            
            # release the nice lock 
            self.zk.cbReleaseNiceLock(cb, queue_name)
        if got_mg_lock:            
            # release the nice lock 
            self.zk.cbReleaseNiceLock(cb_mg, queue_name)
        return session_count
    def checkPig(self, cb, pig_list):
        ''' return true if it is a pig '''
        for pig in pig_list:
            if pig in cb:
                return True
        return False

    def updateTree(self, be_nice, queue_name, just_vuln=False, all_polls=False, just_polls=False, just_povs=False, max_sessions=None,
            no_pigs=False):
        '''
        Look at the entire file repo and update the CB tree to match it.  For testing, not CQE
        Set just_vuln if only want replays of vulnerable reference binaries
        '''
        #TBD delays for testing, remove for production
        pig_list = []
        if no_pigs:
            pig_file = '/usr/share/load-tests/CFE-pigs.txt'
            if not os.path.isfile(pig_file):
                print('missing pig file %s' % pig_file)
            else:
                with open(pig_file) as fh:
                    for line in fh:
                        pig_list.append(line.strip())
        cb_sleep = 0
        pov_sleep = 0
        session_count = 0
        if not os.path.exists(self.cfg.cb_dir):
            print 'missing directory: %s' % self.cfg.cb_dir
            exit(1)
        cbs = os.listdir(self.cfg.cb_dir)
        cbs.sort()
        sql = accessSQL.accessSQL(None, self.lgr)
        cc_con = sql.connectCC(self.cfg.cc_db_name)
        for cb in cbs:
            if not self.checkPig(cb, pig_list):
                session_count = session_count + self.oneCB(cb, be_nice, queue_name, just_vuln, all_polls, just_polls, 
                    just_povs, max_sessions)
        return session_count

    def doCompetitors(self, cb, cb_mg, pov_sleep, be_nice, queue_name, got_cb_lock, got_mg_lock, session_count, just_povs):
        '''
        Handle rcbs and povs from competitors
        ''' 
        self.lgr.debug('doCompetitors for %s' % cb)
        cmp_dir = '%s/%s/%s' % (self.cfg.cb_dir, cb, szk.COMPETITOR)
        if os.path.isdir(cmp_dir):
            cmps = os.listdir(cmp_dir)
            for competitor in cmps:
                c_pov_dir = cmp_dir+'/%s/%s' % (competitor, szk.POVs)
                #print 'check c_pov_dir %s' % c_pov_dir
                if os.path.isdir(c_pov_dir):
                    # do PoVs generated by this competitor
                    competitor_povs = os.listdir(c_pov_dir)
                    for pov_d_name in competitor_povs:
                        pov_f_name = pov_d_name+'.xml'
                        if self.isPOV(pov_f_name):
                           self.lgr.debug('do pov %s for CB %s' % (pov_f_name, cb))
                           time.sleep(pov_sleep)
                           #pov = pov_f_name[:len(pov_f_name)-4]
                           pov = pov_f_name
                           put_pov, got_nice = self.rpm.putReplay(cb, pov, be_nice, queue_name, self.checksum)
                           if put_pov:
                               session_count = session_count + 1
                               got_cb_lock = got_cb_lock or got_nice
                           if cb_mg is not None:
                               put_pov, got_nice = self.rpm.putReplay(cb_mg, pov, be_nice, queue_name, self.checksum)
                               if put_pov:
                                   session_count = session_count + 1
                                   got_mg_lock = got_mg_lock or got_nice
                else:
                    print 'no competitor pov files at %s' % c_pov_dir
                c_cb_dir = cmp_dir+'/%s/%s' % (competitor, szk.CBs)
                #print 'check c_pov_dir %s' % c_pov_dir
                if not just_povs and os.path.isdir(c_cb_dir):
                    # do CBs generated by this competitor
                    competitor_cbs = os.listdir(c_cb_dir)
                    if len(competitor_cbs) > 1:
                        print 'more than one mitigated cb for competitor at %s' % c_cb_dir
                        #exit(1)
                    for cb_f_name in competitor_cbs:
                        should_be = cb+'_'+competitor
                        if not cb_f_name.startswith(should_be):
                            print 'doCompetitors unexpected cb name in %s: %s' % (c_cb_dir, cb_f_name)
                            if not self.cfg.cfe:
                                exit(1)
                            else:
                                continue
                        try:
                           cb_path = szk.CBS_NODE+"/"+cb_f_name
                           self.zk.zk.create(cb_path, '', None, 
                                    False, False, False) 
                           self.lgr.debug("putMonitor create cb configuration file at %s for cb %s" % (cb_path, cb_f_name))
                           self.rpm.multiBinaryCB(cb_path, cb_f_name)
                        except kazoo.exceptions.NodeExistsError:
                           pass

                        num_sessions = self.assignPollsToCB(cb, cb_f_name, be_nice, queue_name)
                        session_count = session_count + num_sessions
                        num_sessions = self.assignPoVsToCB(cb, cb_f_name, be_nice, queue_name)
                        session_count = session_count + num_sessions
                else:
                    print 'no competitor mitigated CB files at %s (or just_povs selected)' % c_pov_dir
        else:
            print 'no competitor replay files for %s' % cmp_dir
        return got_cb_lock, got_mg_lock, session_count

    ''' only for mass creation of simulated competitor sets, otherwise not used '''
    def assignPollsToCB(self, common_name, cb, be_nice, queue_name):
        num_sessions = 0
        a_poll_dir = '%s/%s/%s/%s' % (self.cfg.cb_dir, common_name, szk.AUTHOR, szk.POLLs)
        print 'in assignPollsToCB for common %s, and cb %s.   a_poll_dir is %s' % (common_name, cb, a_poll_dir)
        if os.path.isdir(a_poll_dir):
            author_polls = os.listdir(a_poll_dir)
            for poll_d_name in author_polls:
                if self.isPoll(poll_d_name+'.xml'):
                   put_poll, got_nice = self.rpm.putReplay(cb, poll_d_name, be_nice, queue_name, self.checksum)
                   if put_poll:
                       print 'assignPollsToCB putReplay %s to %s' % (poll_d_name, cb)
                       num_sessions = num_sessions+1
        return num_sessions

    def assignPoVsToCB(self, common_name, cb, be_nice, queue_name):
        session_count = 0
        a_pov_dir = '%s/%s/%s/%s' % (self.cfg.cb_dir, common_name, szk.AUTHOR, szk.POVs)
	print('in assignPoVsToCB for common %s, and cb %s.   a_pov_dir is %s' % (common_name, cb, a_pov_dir))
        self.lgr.debug('in assignPoVsToCB for common %s, and cb %s.   a_pov_dir is %s' % (common_name, cb, a_pov_dir))
        if os.path.isdir(a_pov_dir):
            author_povs = os.listdir(a_pov_dir)
            for pov_d_name in author_povs:
                pov_f_name = pov_d_name+'.xml'
                self.lgr.debug('assignPoVsToCB check author_povs: %s' % pov_f_name)
                if self.isPOV(pov_f_name):
                   #pov = pov_f_name[:len(pov_f_name)-4]
                   pov = pov_f_name
                   self.lgr.debug('assignPoVsToCB put pov for %s' % pov)
                   put_pov, got_nice = self.rpm.putReplay(cb, pov, be_nice, queue_name, self.checksum)
                   if put_pov:
                       session_count = session_count + 1
        else:
            print 'no author pov files for %s' % a_pov_dir
        return session_count

    '''
        Assuming a competitors mitigated CB and PoV have already been put into the file system,
        create the zookeper nodes for the replays needed to clear the competitors package.
        "replays" is a list of polls (or povs) that should be run against the mitigated CB
        pov is the competitor pov that should be run against the unmitigated original CB
        If the given set already exists, nothing happens and the function returns.
    '''
    def updateTreeCompetitorCB(self, team_name, cb_name, version, replays, pov):
       common = utils.getCSID(cb_name)
       if replays is not None and pov is not None:
           set_name = self.team_sets.addTeamSet(team_name, common, version, pov, cb_name, replays)
           if set_name is None:
               self.lgr.debug("team set alreay exists "+cb_name)
               return
           else:
               self.lgr.debug("team set adding sequence "+set_name)
       path_name = utils.rmBinNumFromName(cb_name)
       cb_path = szk.CBS_NODE+"/"+path_name
       try:
           self.zk.zk.create(cb_path, '', None, 
               False, False, False) 
           self.lgr.debug("putMonitor updateTreeCompetitorCB create cb configuration file at %s for cb %s" % (cb_path, cb_name))
           self.rpm.multiBinaryCB(cb_path, cb_name)
       except kazoo.exceptions.NodeExistsError:
           self.lgr.debug('updateTreeCompetitorCB, cb already in zk:%s ' % cb_path)
           return
       ''' put pov for the original CB and author polls for the replacement binary 
           write replacemnt set name into replay node for use by drone to find the competitor set node
       '''
       if pov is not None:
           put_pov, got_nice = self.rpm.putReplay(common, pov, False, szk.FORENSICS, self.checksum, set_name)
           if self.cfg.pov_vs_patched:
               put_pov, got_nice = self.rpm.putReplay(common+'_MG', pov, False, szk.FORENSICS, self.checksum)
       if replays is not None:
           for replay in replays:
               put_poll, got_nice = self.rpm.putReplay(cb_name, replay, False, szk.FORENSICS, self.checksum, set_name)

    def setAlreadyVetted(self, cfg_file):
        fname = os.path.splitext(cfg_file)[0]+'.vet'
        done_file = os.path.join(self.done_path, fname)
        tmp_done_file = done_file+'.forensics_tmp'
        self.lgr.debug('putMonitor, setAlreadyVetted %s' % tmp_done_file)
        with open(tmp_done_file, 'w') as dfh:
            dfh.write('PASS\n')
            dfh.write('replays previously vetted, refer to those results and ignore the "pass"')

    '''
        Assuming the referenced rcb, filters & polls have already been put into the file system,
        create the zookeper nodes for the replays needed to vet the replays named in the given
        config file.
        The config file is also added as a team set.
        If the given set already exists, nothing happens and the function returns.
        NOTE cset_cfg is from monitorLibs/cfeCsetConfig
    '''
    def updateTreeCompetitorCFE(self, cset_cfg, cfg_file_name):
       cb_binaries = cset_cfg.getRCBNames()
       cb_binaries_paths = cset_cfg.getRCBRepo()
       cb_name_0 = cb_binaries[0]
       cb_name = utils.rmBinNumFromName(cb_name_0)
       self.lgr.debug('updateTreeCompetitorCFE, cb_name_0 is %s rmBin got %s' % (cb_name_0, cb_name))
       rules = cset_cfg.getIDSRepo()
       replay_count = 0
       if rules is not None:
           if os.path.getsize(rules) > 0:
               rules = os.path.basename(cset_cfg.getIDS())
           else:
               rules = None
       team_name = cset_cfg.getTeamId()
       common_name = cset_cfg.getCommonName()
       pov = cset_cfg.getPov()
       polls = None
       if pov is not None: 
           pov = os.path.basename(pov)
           if self.rpm.isReplayDone(cb_name, pov, rules=rules):
               self.setAlreadyVetted(cfg_file_name)
               self.lgr.debug('updateTreeCompetitorCFE, pov for %s previously vetted' % cfg_file_name)
               return 0
       else:
           polls = self.getCBPolls(common_name)
           if len(polls) > 0:
               if self.rpm.isReplayDone(cb_name, polls[0]):
                   self.setAlreadyVetted(cfg_file_name)
                   self.lgr.debug('updateTreeCompetitorCFE, polls for %s previously vetted' % cfg_file_name)
                   return 0
           else:
               self.lgr.error('updateTreeCompetitorCFE, could not find polls for %s' % common_name)
               return 0
       pov_team = ''
       pov_team_num = cset_cfg.getPovTeam()
       if pov_team_num is not None: 
           pov_team = str(pov_team_num)

       pov_config = cset_cfg.getPovConfig()
       round_id = cset_cfg.getRoundId()
       set_id = self.team_sets.addTeamSetCFE(str(team_name), cb_name, cb_binaries, polls, rules, pov, pov_team, 
                         cfg_file_name, cset_cfg.getGameId(), round_id, pov_config)
       self.sql.addSetCFE(set_id, cfg_file_name, common_name, str(team_name), pov_team, cb_name, pov, round_id)
       self.lgr.debug('putMonitor updateTreeCompetitorCFE added to sql: %s %s' % (str(team_name), cfg_file_name))
       cb_path = szk.CBS_NODE+"/"+cb_name
       try:
           self.zk.zk.create(cb_path, '', None, 
               False, False, False) 
           self.lgr.debug("putMonitor updateTreeCompetitorCFE create cb configuration file at %s for cb %s" % (cb_path, cb_name))
           self.rpm.getBinConfigs(cb_path, cb_binaries_paths)

       except kazoo.exceptions.NodeExistsError:
           self.lgr.debug('updateTreeCompetitorCFE, cb already in zk, must be a pov??? : '+ cb_path)
       ''' put polls for the rcb 
           write replacemnt set name into replay node for use by drone to find the competitor set node
       '''
       if polls is not None and len(polls)>0:
           for poll in polls:
               self.lgr.debug('updateTreeCompetitorCFE for poll %s' % poll)
               put_poll, got_nice = self.rpm.putReplay(cb_name, poll, False, szk.FORENSICS, self.checksum, set_id, rules=rules)
               if put_poll:
                   replay_count += 1
       else:
           checksum = self.checksum
           if self.pov_checksum is not None:
               checksum = self.pov_checksum
           self.lgr.debug('updateTreeCompetitorCFE for pov %s checksum %s' % (pov, checksum))
           put_pov, got_nice = self.rpm.putReplay(cb_name, pov, False, szk.FORENSICS, checksum, set_id, rules=rules)
           if put_pov:
               replay_count += 1
       self.lgr.debug('updateTreeCompetitorCFE added %d replays' % replay_count)
       if replay_count == 0:
           self.team_sets.setNeededZero(set_id) 
       return replay_count
           

    def getCBPolls(self, common_name):
        retval = []
        a_poll_dir = '%s/%s/%s/%s' % (self.cfg.cb_dir, common_name, szk.AUTHOR, szk.POLLs)
        if os.path.isdir(a_poll_dir):
            author_polls = os.listdir(a_poll_dir)
            retval = author_polls[:2]
        else:
            self.lgr.debug('getCBPolls found no polls for '+common_name)
        return retval

    def close(self):
        if self.sql is not None:
            self.sql.close()
