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
import xml.etree.ElementTree as ET
import kazoo
import os
import sys
import time
import utils
import forensicEvents
import logging
import json
'''
    Manage the team set nodes to encourage the consumption of CB/replay nodes in a
    sequence that completes competitor sets (CB binaries & PoV) in the order that they were
    submitted.  Uses zookeeper to maintain a queue-like structure of sequential nodes, each
    of which contain xml identifying each CB/replay in the set.  The names of these nodes
    are intended to be stored in the replay nodes themselves (in the CBs tree) so that the
    monitor that completes the final replay within a competitor set will notify the world that the set is
    complete.
'''
SET_DONE='done'
SET_LOGGED='logged'
class teamSets():
    def __init__(self, zk, lgr=None):
        self.zk = zk
        self.lgr = lgr
        self.prev_team_set = None
        self.prev_team_value = None
        if lgr is None:
            self.lgr = logging
        self.lgr.debug('teamSets init')
        
    def addTeamSet(self, team_name, common, version, pov, cb_name, replays):
       '''
       Add a team set to the queue.  The team set is a list of CB/replay pairs including:
       The original CB (common) / pov
       The given replacement CB (cb_name) paired with a selected set of Polls (replays) 
       '''
       set_path = szk.TEAM_SETS+'/teamset_'
       #set_path = szk.TEAM_SETS+'/'+cb_name
       # we are done when each replay and the pov have completed.
       num_replays = len(replays)
       if pov is not None:
           num_replays += 1
       the_string = self.getEncodedPackage(team_name, version, cb_name, replays, common, pov, num_replays, 0)
       #the_string = '%d' % num_replays
       set_name = None
       try:
           #Create sequence number as set name
           set_name = self.zk.zk.create(set_path, the_string, acl=None, ephemeral=False, sequence=True, makepath=False) 
           self.lgr.debug('teamSets, addTeamSet created team set at path %s' % set_name)
       except kazoo.exceptions.NoNodeError:
           self.lgr.error('could not create sequence node at %s' % set_path)
           return None
       bs = os.path.basename(set_name).encode('latin-1')
       return bs


    def addTeamSetCFE(self, team_name, cb_name, cb_binaries, polls, rules, pov, pov_team, cfg_file_name, game_id, round_id, pov_config):
       set_path = szk.TEAM_SETS+'/teamset_'
       #set_path = szk.TEAM_SETS+'/'+cb_name
       # we are done when each replay and the pov have completed.
       num_replays = 1
       if polls is not None and len(polls)>0:
           num_replays = len(polls)
       print('call getEncode...cfg_file_name is %s ' % cfg_file_name)
       the_string = self.getEncodedPackage(team_name, '0', cb_name, polls, None, pov, num_replays, 0, 
           cb_binaries = cb_binaries, rules = rules, cfg_file_name = cfg_file_name, game_id = game_id, pov_team=pov_team, pov_config=pov_config, round_id=round_id)
       set_name = None
       try:
           #Create sequence number as set name
           set_name = self.zk.zk.create(set_path, the_string, acl=None, ephemeral=False, sequence=True, makepath=False) 
           self.lgr.debug('teamSets, addTeamSet created team set at path %s' % set_name)
       except kazoo.exceptions.NoNodeError:
           self.lgr.error('could not create sequence node at %s' % set_path)
           return None
       bs = os.path.basename(set_name).encode('latin-1')
       return bs

    def vetTheReplay(self, cb_name, replay, log):
        '''
        Determine if a given replay passes forensics vetting
        TBD record problem in DB
        '''
        retval = True
        try:
            root = ET.fromstring(log)
        except:
            self.lgr.error('teamSets, vetTheReplay could not parse %s' % log)
            return False
        load_fail = root.find('load_fail')
        # only worry about load failure on service polls. Lame POV could keep
        # all bins in a CB from loading 
        if load_fail is not None and not replay.startswith('POV'):
            self.lgr.debug('teamSets, vetTheReplay found load fail of %s or %s' % (cb_name, replay))
            retval = False
        events = root.findall('event')
        for event in events:
            event_type_entry = event.find('event_type')
            event_type = int(event_type_entry.text)
            self.lgr.debug("teamSets, vetTheReplay vetting %s %s event type: %d (%s)" % (cb_name, replay, 
                event_type, forensicEvents.stringFromEvent(event_type)))
            if event_type >= forensicEvents.CRITICAL_EVENT:                    
                self.lgr.critical('Vetting finds %s and rejects %s' % (forensicEvents.stringFromEvent(event_type), log))
                self.zk.logCritical('Vetting finds %s and rejects %s' % (forensicEvents.stringFromEvent(event_type), log))
                retval = False
        return retval

    def checkCompetitorSet(self, cb_name, replay, log, set_name):
        '''
        See if this replay is part of a team submittal set.  If so, and this is the last replay
        in the package, mark the set as done and report results to the database.  Intended for use by the cgcMonitor.
        '''
        retval = False
        #set_name, dum = self.zk.zk.get(path)
        vetOK = self.vetTheReplay(cb_name, replay, log)
        self.lgr.debug( 'teamSets, checkCompetitorSet set for %s (%s & %s) vetOK: %r , log is %s' % (set_name, cb_name, replay, vetOK, log))
        # indicate if the pov or a replacement CB failed vetting
        replay_failed_vet = None
        if not vetOK:
            if self.zk.isPoV(replay):
               replay_failed_vet = 'pov'
            elif replay.startswith("SP"):
               replay_failed_vet = 'rcb'
            else:
               self.lgr.critical("checkCompetitorSet, unknown replay type failed vetting: %s" % replay)
            self.lgr.debug('teamSets, checkCompetitorSet, replay failed vetting: %s %s' % (cb_name, replay))
         
        if set_name is not None and len(set_name) > 0:
            # look at the set name node to see if we are the final replay
            set_path = szk.TEAM_SETS+'/'+set_name
            # loop until we can write
            done = False
            while not done:
                #self.lgr.debug('about to call getSetCounts')
                ss = self.getSetCounts(set_path, True, replay_failed_vet)
                #print 'back from  call'
                self.lgr.debug( 'competitor set for %s need: %d  current %d' % (set_name, ss.need, ss.current_count))
                if ss.final_replay:
                    # we are last, update node (though not needed for protocol) and report finish
                    #print 'competitor set done for '+set_name
                    self.lgr.debug( 'competitor set done for '+set_name)
                    done_set = set_path+'/' + SET_DONE
                    try:
                        self.zk.zk.set(set_path, ss.the_string, ss.stat.version)
                        done = True
                        try:
                            self.zk.zk.create(done_set)
                            #self.lgr.debug( 'competitor set done created at '+done_set)
                        except kazoo.exceptions.NodeExistsError:
                            self.lgr.error('could not set done node on teamset %s' % set_name)
                        except kazoo.exceptions.NoNodeError:
                            self.lgr.error('could not set done node on teamset %s' % set_name)
                            #exit(1)
                        #self.sql.setDone(team_name, common, version, 'dumb rec')

                        retval = True
                    except kazoo.exceptions.BadVersionError:
                        print 'error setting what should be the final replay for set %s, exiting' % set_name
                        self.lgr.error('error setting what should be the final replay for set %s, exiting' % set_name)
                        #exit(1)
                else:
                    try:
                        self.zk.zk.set(set_path, ss.the_string, version=ss.stat.version)
                        self.lgr.debug('competitor set %s incremented to %d %s' % (set_name,
                            ss.current_count, ss.the_string))
                        done = True
                    except kazoo.exceptions.BadVersionError:
                        stat = self.zk.zk.exists(set_path)
                   
                        print 'collision trying to update set %s, try again' % set_name
                        self.lgr.debug( 'collision trying to update set %s  tried %d  was %d  try again' % (set_name, ss.stat.version, stat.version))
                        #time.sleep(3)
        else:
            self.lgr.debug('teamSets no set name for %s %s' % (cb_name, replay))
        return retval

    class teamsetStatus():
        def __init__(self, need, current_count, stat, team_name, common, version, rcb, pov, rcb_failed_vet, pov_failed_vet, 
                      the_string, final_replay, time_start, cfg_file=None, time_finish=None, game_id=None):
            self.need = need
            self.current_count = current_count
            self.stat = stat
            self.team_name = team_name
            self.common = common
            self.version = version
            self.rcb = rcb
            self.pov = pov
            self.rcb_failed_vet = rcb_failed_vet
            self.pov_failed_vet = pov_failed_vet
            self.the_string = the_string
            self.final_replay = final_replay
            self.cfg_file = cfg_file
            self.time_start = time_start
            self.time_finish = time_finish
            self.game_id = game_id
        def isDone(self):
            retval = False
            if self.need == self.current_count:
                retval = True
            return retval
        def toString(self):
            if self.cfg_file is None:
                retval = 'team: %s csid: %s  version: %s rcb: %s  pov: %s rcb_failed_vet: %r  pov_failed_vet: %r  need: %d  got: %d' \
                    % (self.team_name, self.common, self.version, self.rcb, self.pov, self.rcb_failed_vet, self.pov_failed_vet, 
                    self.need, self.current_count)
            else:
                ''' cfe style '''
                time_stamp =''
                if self.time_start is not None:
                    time_stamp = 'time: %s-' % (self.time_start)
                    if self.time_finish is not None:
                        time_stamp = time_stamp+self.time_finish
                retval = 'team: %s cfg_file: %s rcb: %s  pov: %s rcb_failed_vet: %r  pov_failed_vet: %r  need: %d  got: %d cfg: %s  game: %s %s' \
                    % (self.team_name, self.cfg_file, self.rcb, self.pov, self.rcb_failed_vet, self.pov_failed_vet, 
                    self.need, self.current_count, self.cfg_file, self.game_id, time_stamp)
            return retval
   
    def getSetCounts(self, set_path, record_it=False, replay_failed_vet=None):
        '''
        Read a team set node and return information including the current count of the 
        replays that have been completed against this set.  NOTE, if record_it, then
        the count will include
        an increment for the caller, unless the count already equals the number of
        replays in the set.  vetted_replay is the replay that successfully vetted, None
        if the associated replay failed vetting
        ''' 
        value = None
        stat = None
        final_replay = False
        try:
            value, stat = self.zk.zk.get(set_path)
        except kazoo.exceptions.NoNodeError:
            print 'getSetCounts error accessing team set node %s, exiting' % set_path
            self.lgr.error('getSetCounts error accessing team set node %s ' % set_path)
            exit(1)
        root = ET.fromstring(value)
        need = int(root.find('needed').text)
        current_count_element = root.find('current_count')
        current_count = int(current_count_element.text)
        if(record_it and current_count < need):
            current_count += 1
            if current_count == need:
                final_replay = True
                time_stamp_element = ET.SubElement(root, 'time_finish')
                time_stamp_element.text = str(time.time())
            current_count_element.text = str(current_count)
        team_name = root.find('team_name').text
        common = root.find('common').text
        version = int(root.find('version').text)
        rcb = root.find('rcb').text
        pov = ''
        try:
            pov = root.find('pov').text
        except:
            pass
        rcb_failed_vet = False
        pov_failed_vet = False
        try:
            val = root.find('rcb_failed_vet')
            if val is not None:
                rcb_failed_vet = True
                self.lgr.debug('teamSets getSetCounts, replay_failed_vet rcb already failed')
        except:
            pass
        try:
            val = root.find('pov_failed_vet')
            if val is not None:
                self.lgr.debug('teamSets getSetCounts, replay_failed_vet pov already failed')
                pov_failed_vet = True
        except:
            pass
        if replay_failed_vet is not None:
            self.lgr.debug('teamSets getSetCounts, replay_failed_vet is %s' % replay_failed_vet)
            if replay_failed_vet == 'rcb':
                rcb_failed_vet = True
                rcb_element = ET.SubElement(root, 'rcb_failed_vet')
            elif replay_failed_vet == 'pov':
                pov_failed_vet = True
                pov_element = ET.SubElement(root, 'pov_failed_vet')
            else:
                self.lgr.critical("teamSets getSetCounts unexpected replay_failed vet value %s" % replay_failed_vet)
        
        cfg_file = None
        cfg_file_element = root.find('cfg_file_name')        
        if cfg_file_element is not None:
            cfg_file = cfg_file_element.text 
        time_start = None
        time_finish = None
        time_start_element = root.find('time_start')
        if time_start_element is not None:
            time_start = root.find('time_start').text
            time_finish_element = root.find('time_finish')        
            if time_finish_element is not None:
                time_finish = time_finish_element.text
        

        the_string = ET.tostring(root)
        self.lgr.debug('getSetCounts %s need %d current_count %d  value %s stat.version %d' % (set_path, 
            need, current_count, value, stat.version))
        retval = self.teamsetStatus(need, current_count, stat, team_name, common, version, rcb, pov, 
                                     rcb_failed_vet, pov_failed_vet, the_string, final_replay, time_start, cfg_file = cfg_file, time_finish = time_finish)
        return retval
 
    ''' 
        of the form <team_set>
                      <team_name>BLH</team_name>
                      <common>BLH</common>
                      <version>N</version>
                      <rcb>BLH</rcb>
                      <pov>BLH</pov>
                      <needed>N</needed><current_count>I</current_count>
                      <pair>
                        <cb>CB...</cb><replay>SP...</replay>
                      </pair>
                    </team_set>
    ''' 
    def getEncodedPackage(self, team_name, version, cb, replays, common, pov, needed, current_count, cb_binaries=None, 
           rules=None, cfg_file_name = None, game_id = None, pov_team = None, pov_config = None, round_id=0):
        ''' if cb_binaries exists, this is a cfe package without context in the names '''
        doc = ET.Element('team_set')
        name = ET.SubElement(doc, 'team_name')
        name.text = team_name
        common_element = ET.SubElement(doc, 'common')
        common_element.text = common
        version_element = ET.SubElement(doc, 'version')
        version_element.text = str(version)
        if cb_binaries is None:
            rcb_element = ET.SubElement(doc, 'rcb')
            rcb_element.text = cb
        else:
            ''' cfe style '''
            for cb_bin in cb_binaries:
                rcb_element = ET.SubElement(doc, 'rcb')
                rcb_element.text = cb_bin
            no_context_element = ET.SubElement(doc, 'no_context')
            no_context_element.text = 'true'
            time_stamp_element = ET.SubElement(doc, 'time_start')
            time_stamp_element.text = str(time.time())
        
        if pov is not None:
            pov_element = ET.SubElement(doc, 'pov')
            pov_element.text = pov
            if pov_team is not None:
                pov_team_element = ET.SubElement(doc, 'pov_team')
                pov_team_element.text = pov_team

        needed_element = ET.SubElement(doc, 'needed')
        needed_element.text = '%d' % needed
        count_element = ET.SubElement(doc, 'current_count')
        count_element.text = '%d' % current_count
        if pov is not None:
            pair_element = ET.SubElement(doc, 'pair')
            cb_element = ET.SubElement(pair_element, 'cb')
            if common is not None:
                cb_element.text = common
                replay_element = ET.SubElement(pair_element, 'replay')
                replay_element.text = pov
            elif cb_binaries is not None:
                ''' cfe style '''
                cb_element.text = cb
                replay_element = ET.SubElement(pair_element, 'replay')
                replay_element.text = pov
         
        elif replays is not None:
            for replay in replays:
                pair_element = ET.SubElement(doc, 'pair')
                cb_element = ET.SubElement(pair_element, 'cb')
                cb_element.text = cb
                replay_element = ET.SubElement(pair_element, 'replay')
                replay_element.text = replay
        if rules is not None:
            rules_element = ET.SubElement(doc, 'rules')
            rules_element.text = rules

        if cfg_file_name is not None:
            fname_element = ET.SubElement(doc, 'cfg_file_name')
            fname_element.text = cfg_file_name
        if game_id is not None:
            game_element = ET.SubElement(doc, 'game_id')
            game_element.text = game_id
        round_element = ET.SubElement(doc, 'round_id')
        round_element.text = str(round_id)
        if pov_config is not None:
            pov_config_element = ET.SubElement(doc, 'pov_config')
            js = json.dumps(pov_config, indent=4)
            pov_config_element.text = js

        xml = ET.tostring(doc)
        bs = xml.encode('latin-1')

        return bs

    def getNextTeamSet(self):
        '''
        Search the teamset nodes looking for a CB/replay pair that
        has not already been locked.  Use the TEAM_SET_HINT node
        to avoid starting at the first node in the sequence.
        If a CB/replay pair is found, return it, otherwise return None.
        '''
        cb = None
        replay = None
        path = szk.TEAM_SET_HINT
        try_seq = None
        # get the hint as to where to start
        try:
            value, stat = self.zk.zk.get(path)
            try_seq = int(value)+1
        except kazoo.exceptions.NoNodeError:
            # hint does not yet exist see if there are any nodes, and start with the earliest
            try:
                children = self.zk.zk.get_children(szk.TEAM_SETS)
            except kazoo.exceptions.NoNodeError:
                self.lgr.debug('getNextTeamSet, missing root team set node %s' % szk.TEAM_SETS)
                return None, None, None

            if len(children) > 0:
                children.sort()
                try_seq = utils.seqFromNode(children[0])
                if try_seq is None:
                    self.lgr.debug('getNextTeamSet, could not get try_seq from %s' % children[0])
 
        if try_seq is not None: 
            done = False
            while not done:
                cb, replay, has_node = self.trySetNode(try_seq)
                if cb is not None:
                    self.lgr.debug('getNextTeamSet found replay for %s %s' % (cb, replay))
                    done = True
                elif not has_node:
                    done = True
                else:
                    try_seq += 1
            set_id = '/teamset_%010d' % try_seq
        else:
            self.lgr.debug('getNextTeamSet, could not get try_seq ')
            return None, None, None
        return cb, replay, set_id
      
    def setNeededZero(self, set_id):
        '''
        set the "needed" value to zero for a given set.  Intended for use if the
        replays of a set were already queue from a previous set.   TCB record id
        of that previous set.  For now we just know the replays were queued.
        '''
        path = szk.TEAM_SETS+'/'+set_id
        try:
            value, stat = self.zk.zk.get(path)
        except kazoo.exceptions.NoNodeError:
            self.lgr.error('setNeededZero could not find node at %s' % path)

        root = ET.fromstring(value)
        need_element = root.find('needed')
        need_element.text = '0'
        the_string = ET.tostring(root)
        self.zk.zk.set(path, the_string)
          
    def trySetNode(self, set_seq):
        '''
        Get a lock on the given teamset sequence number.  If a lock is obtained, return
        the cb & replay the corresponds to the obtained lock (they are a list of pairs).  
        Also return a boolean reflecting whether the
        given sequence number has a correpsonding node.
        ''' 
        cb = None
        replay = None
        has_node = True
        set_id = 'teamset_%010d' % set_seq
        path = szk.TEAM_SETS+'/'+set_id
        self.lgr.debug('trySetNode, will try path '+path)
        try:
            value, stat = self.zk.zk.get(path)
        except kazoo.exceptions.NoNodeError:
            self.lgr.debug('trySetNode, no node at '+path)
            has_node = False
        if has_node:    
            root = ET.fromstring(value)
            need = int(root.find('needed').text)
            current_count = int(root.find('current_count').text)
            if(need > current_count):
                children = self.zk.zk.get_children(path)
                if(len(children) < need):
                    set_name = self.zk.zk.create(path+'/lock_', '', None, False, True, False) 
                    seq = utils.seqFromNode(set_name)
                    #self.lgr.debug('trySetNode, need %d, got seq of %d' % (need, seq))
                    # zk sequences start at 0 
                    if seq < need:
                        replays = root.findall('pair')
                        my_replay = replays[seq]
                        try:
                            cb = my_replay.find('cb').text
                        except:
                            self.lgr.error('trySetNode, could not get cb from %s' % value)
                            exit(1)
                        try:
                            replay = my_replay.find('replay').text
                        except:
                            self.lgr.error('trySetNode, could not get replay from %s' % value)
                            exit(1)
                        if seq == need-1:
                            # we took the last cb, update the hint
                            path = szk.TEAM_SET_HINT
                            bs = str(set_seq).encode('latin-1')
                            try:
                                self.zk.zk.set(path, bs)
                                self.lgr.debug('trySetNode updated the hint to %d' % set_seq)
                            except kazoo.exceptions.NoNodeError:
                                try:
                                    self.zk.zk.create(path,bs)
                                except kazoo.exceptions.NodeExistsError:
                                    pass
            else:
                self.lgr.debug('trySetNode tried %s, but is was all taken' % path)
        return cb, replay, has_node

    def deleteTestSets(self, min_team_id):
        test_sets = self.getTestSets(min_team_id)
        for ts in test_sets:
            path = szk.TEAM_SETS+'/'+ts
            print('deleteTestSets delete %s' % path)
            self.zk.zk.delete(path, recursive=True)
         

    def getTestSets(self, min_team_id):
        children = self.zk.zk.get_children(szk.TEAM_SETS)
        retval = list(children)
        for child in children:
            value, stat = self.zk.zk.get(szk.TEAM_SETS+'/'+child)
            root = ET.fromstring(value)
            team = root.find('team_name').text
            team_id = int(team)
            print('team id to test is %d' % team_id)
            if team_id < min_team_id:
                retval.remove(child)
        return retval
                
            
    def areGameSetsDone(self, game_id):
        '''
        Determine if all replays within all team sets for a given game_id are done
        '''
        self.lgr.debug('areGameSetsDone for game %s' % game_id)
        children = self.zk.zk.get_children(szk.TEAM_SETS)
        children.sort()
        replays_done = 0
        replays_needed = 0
        for child in children:
            value, stat = self.zk.zk.get(szk.TEAM_SETS+'/'+child)
            root = ET.fromstring(value)
            this_game_id = root.find('game_id') 
            #self.lgr.debug('areGameSetsDone, compare %s to %s' % (this_game_id.text, game_id))
            if this_game_id is not None and this_game_id.text == game_id:
                need = int(root.find('needed').text)
                current_count = int(root.find('current_count').text)
                replays_done += current_count
                replays_needed += need
        self.lgr.debug('areGameSetsDone replays_done: %d  needed: %d' % (replays_done, replays_needed))
        return replays_done, replays_needed
     

    def getTeamSetStatus(self, incomplete=False, not_cleared=False):
        '''
        Display team set status, optionally only incomplete sets, or sets
        having replays that failed vetting
        ** altered for CFE ***
        '''
        children = self.zk.zk.get_children(szk.TEAM_SETS)
        children.sort()
        total_sets = len(children)
        num_done = 0
        num_in_progress = 0
        current_game = None
        for child in children:
            #set_path = szk.TEAM_SETS+'/'+child
            #ss = self.getSetCounts(set_path)
            #print ss.toString()
            value, stat = self.zk.zk.get(szk.TEAM_SETS+'/'+child)
            root = ET.fromstring(value)
            need = int(root.find('needed').text)
            current_count = int(root.find('current_count').text)
            is_pov = False
            failed_vet = False
            pov = root.find('pov')
            if pov is not None:
                is_pov = True
                val = root.find('pov_failed_vet')
                if val is not None:
                    failed_vet = True
            else:
                val = root.find('rcb_failed_vet')
                if val is not None:
                    failed_vet = True
                
            fname = '' 
            cfg_file = root.find('cfg_file_name') 
            if cfg_file is not None and cfg_file.text  is not None:
                fname = 'cfg_file: '+cfg_file.text
            else:
                print("NO CONFIG FILE NAME")
            game_id = root.find('game_id') 
            if game_id is not None and game_id.text != current_game:
                print('game: %s' % game_id.text)
                current_game = game_id.text
            if not not_cleared:
                if not incomplete or need != current_count:
                    print 'set: %s need: %d got: %d failed_vet: %r %s' % (child, need, current_count, failed_vet, fname)
            elif failed_vet:
                print 'set: %s failed_vet: %r  %s' % (child, failed_vet, fname)
                self.showTeamReplays(child)
                
            if current_count == need:
                num_done += 1
            elif current_count > 0:
                num_in_progress += 1
        return total_sets, num_done, num_in_progress        

    def getReplayPairs(self, set_path):
        try:
            value, stat = self.zk.zk.get(set_path)
        except kazoo.exceptions.NoNodeError:
            print('error accessing team set node %s, exiting' % set_path)
            self.lgr.error('error accessing team set node %s, exiting' % set_path)
            exit(1)
        root = ET.fromstring(value)
        replays = root.findall('pair')
        return replays

    def getReplays(self, team_set):
        node = szk.TEAM_SETS+'/'+team_set
        retval = []
        try:
            value, stat = self.zk.zk.get(node)
        except kazoo.exceptions.NoNodeError:
            print('error accessing team set node %s, exiting' % set_path)
            self.lgr.error('error accessing team set node %s, exiting' % set_path)
            exit(1)
        root = ET.fromstring(value)
        replays = root.findall('pair')
        for r in replays:
            retval.append(r.find('replay').text)
        return retval

    def cleanTeamSets(self):
        # delete entire node tree so sequence numbers reset
        try:
            self.zk.zk.delete(szk.TEAM_SETS, recursive=True)
        except:
            pass
        try:
            self.zk.zk.delete(szk.TEAM_SET_HINT)
        except:
            pass

    def clearAllLogged(self):
        children = self.zk.zk.get_children(szk.TEAM_SETS)
        for child in children:
            child_path = szk.TEAM_SETS + '/' + child
            log_done_path = child_path +'/'+SET_LOGGED
            try:
                self.zk.zk.delete(log_done_path)
            except kazoo.exceptions.NoNodeError:
                pass


    def setLogged(self, path):
        try:
            self.zk.zk.create(path+'/'+SET_LOGGED)
        except kazoo.exceptions.NodeExistsError:
            self.lgr.debug('setLogged found SET_LOGGED already created for %s' % path)

    def watchSets(self, done_callback_watch, done_callback_direct, new_set_callback):
        try:
            children = self.zk.zk.get_children(szk.TEAM_SETS, watch = new_set_callback)
        except kazoo.exceptions.NoNodeError:
            self.lgr.debug('watchSets found no TEAM_SETS node')
            return
        for child in children:
            child_path = szk.TEAM_SETS + '/' + child
            set_done_path = child_path+'/'+SET_DONE
            log_done_path = child_path +'/'+SET_LOGGED
            if not self.zk.zk.exists(log_done_path):
                #print 'log not done for '+child   
                self.lgr.debug('log not done for '+child)
                if self.zk.zk.exists(set_done_path, watch = done_callback_watch):
                    #print 'set was done for '+child   
                    self.lgr.debug('set done for '+child)
                    done_callback_direct(child_path)
                else:
                    pass
                    self.lgr.debug('set NOT done for '+child+' should be a watch set on '+set_done_path)
                    #print 'set Not done for '+child 
            else:
                self.lgr.debug('log done for '+child)

    def checkCache(self, team_set):
        if team_set != self.prev_team_set:
            node = szk.TEAM_SETS+'/'+team_set
            try:
                self.prev_team_value, stat = self.zk.zk.get(node)
            except kazoo.exceptions.NoNodeError:
                self.lgr.error('teamSEts, checkCache, no team set node at %s' % node)
            self.prev_team_set = team_set

    def getGeneric(self, team_set, tag):
        self.checkCache(team_set)
        root = ET.fromstring(self.prev_team_value)
        retval = None
        generic = root.find(tag)
        if generic is not None:
            retval = generic.text
        return retval

    def getRoundId(self, team_set):
        retval = self.getGeneric(team_set, 'round_id')
        if retval is None:
            retval = 0
        return retval

    def getTeamRules(self, team_set):
        return self.getGeneric(team_set, 'rules')

    def getTeamRCBs(self, team_set):
        self.checkCache(team_set)
        root = ET.fromstring(self.prev_team_value)
        binaries = root.findall('rcb')
        retval = []
        for b in binaries:
            retval.append(b.text)
        return retval

    def getCB(self, team_set):
        self.checkCache(team_set)
        root = ET.fromstring(self.prev_team_value)
        pairs = root.findall('pair')
        for p in pairs:
            cb = p.find('cb')
            return cb
        return None

    def getTeamNoContext(self, team_set):
        self.checkCache(team_set)
        root = ET.fromstring(self.prev_team_value)
        retval = False
        no_context = root.find('no_context')
        if no_context is not None and no_context.text == 'true':
            retval = True
        return retval

    def getTeamId(self, team_set):
        return self.getGeneric(team_set, 'team_name')

    def getPovTeamId(self, team_set):
        return self.getGeneric(team_set, 'pov_team')

    def getPov(self, team_set):
        return self.getGeneric(team_set, 'pov')

    def getPovConfig(self, team_set):
        return self.getGeneric(team_set, 'pov_config')

    def getGameId(self, team_set):
        return self.getGeneric(team_set, 'game_id')

    def getConfigFileName(self, team_set):
        return self.getGeneric(team_set, 'cfg_file_name')


    def showTeamReplays(self, team_set):
        node = szk.TEAM_SETS+'/'+team_set
        value, stat = self.zk.zk.get(node)
        root = ET.fromstring(value)
        game_id = root.find('game_id')
        fname=''
        cfg_file = root.find('cfg_file_name') 
        if cfg_file is not None:
            fname = cfg_file.text
        if game_id is not None:
            round_id = self.getRoundId(team_set)
            team_id = self.getTeamId(team_set)
            pov_team = self.getPovTeamId(team_set)
            pov_str = 'team: %s' % team_id
            if pov_team is not None:
                pov_str = 'pov from %s against %s' % (pov_team, team_id)
            
            print('game: %s cfg: %s set: %s  round %s  %s' % (game_id.text, fname, team_set, round_id, pov_str)) 
        rules_str = ''
        rules = root.find('rules')
        if rules is not None:
            rules_str = rules.text
        replays = root.findall('pair')
        for r in replays:
            cb = r.find('cb')
            replay = r.find('replay')
            if cb is not None and cb.text is not None:
                print cb.text+' '+replay.text+' '+rules_str
                self.zk.showLog(szk.CBS_NODE+'/'+cb.text, replay.text, no_header=True)
            else:
                print('no cb in %s' % value)
            
    def listTeamSets(self, show_log, team_set=None, incomplete=False, not_cleared=False):
        if team_set is not None:
            self.showTeamReplays(team_set)
        else:
            total_sets, num_done, num_in_progress = self.getTeamSetStatus(incomplete, not_cleared)
            print 'total sets: %d  done: %d  in progress: %d' % (total_sets, num_done, num_in_progress)
            if show_log: 
                children = self.zk.zk.get_children(szk.TEAM_SETS)
                children.sort()
                for child in children:
                    print child
                    self.showTeamReplays(child)
                
    def getTeamSets(self):
        retval = []
        children = self.zk.zk.get_children(szk.TEAM_SETS)
        children.sort()
        for child in children:
            retval.append(child)
        return retval




