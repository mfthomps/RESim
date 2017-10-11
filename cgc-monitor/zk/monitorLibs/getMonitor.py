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
import teamSets
import sys
import time
import json
from threading import Thread, Lock, Condition
from os import path
import kazoo
import xml.etree.ElementTree as ET
import dbgQueue
import replayMgr
import logging
import povJson
'''
    Get a PoV or Service poll package by parsing the
    CGC node hierarchy (and dbgQueue) looking for polls or PoVs that
    have not been run.  The returned object is an
    xml-encoded package.  Prior to brute force searching
    for replays, the teamSets module is referenced in order
    to sequence replay consumption such that team sets are 
    completed in the order that they were submitted.
    Intended to be used by multiple consumers.  Nodes 
    representing PoVs and Service polls are marked as
    consumed via locks. 
'''
class getMonitor():
    __watched_cbs = {}
    __package_cb = None
    __done_cbs = []
    ''' optimization to avoid reading done nodes when first starting '''
    __done_replays = {}
    __clue = None
    def __init__(self, szk, cfg, lgr, use_dbg_queue=False, rpm = None, any_config=False, team_sets=None, only_client=None):
        self.counter_lock = Lock()
        self.counter = 0
        self.szk = szk
        self.cfg = cfg
        if rpm is None:
            self.rpm = replayMgr.replayMgr(szk, cfg)
        else:
            self.rpm = rpm
        self.use_dbg_queue = use_dbg_queue
        self.any_config = any_config
        if lgr is None:
            self.lgr = logging
        else:
            self.lgr = lgr
        self.doc = None
        if team_sets is None:
            self.team_sets = teamSets.teamSets(self.szk, lgr=self.lgr)
        else:
            self.team_sets = team_sets
        self.dbg_queue = dbgQueue.dbgQueue(self.szk, self.lgr)
        self.checksum = None
        self.only_client = only_client
        self.lgr.debug('getMonitor, start.  use_dbg_queue is %r' % use_dbg_queue)

    def readCounter(self):
        self.counter_lock.acquire()
        mycount = self.counter
        self.counter_lock.release()
        return mycount

    def incCounter(self):
        self.counter_lock.acquire()
        self.counter += 1
        retval = self.counter
        self.counter_lock.release()
        return retval

    def waitCounter(self, wait_for, max_time=None):
        '''
        wait until the counter is greater than the given value, or a timeout is reached
        Return true if the wait_for value is reached
        '''
        my_count = 0
        increment = 1
        loops = 0
        retval = False
        while my_count <= wait_for and (max_time is None or loops < max_time):
            my_count = self.readCounter()
            #self.lgr.debug('putPackages waitCounter wait for %d count now is %d' % (wait_for, my_count))
            if my_count <= wait_for:
                time.sleep(increment)
                loops += increment
            else:
                retval = True
                self.lgr.debug('count greater than %d' % wait_for)
        return retval
    
    '''
        Look for a CB with new PoVs or polls, starting with CB's we are already watching
    '''
    def handleCB(self, do_watch, be_nice, second_look, singles, any_checksum=False):
        self.lgr.debug('in handleCB')
        watch = None
        if do_watch:
            watch = self.watchCBs

        # look for new action in CBs we are already watching
        got_a_replay = False
        if self.__clue is not None:
             got_a_replay = self.handleReplay(szk.CBS_NODE+"/"+self.__clue, do_watch, 
                be_nice, singles, any_checksum)
        else:
             pass

        self.__clue = None

        if not got_a_replay and not second_look:
            for cb in self.__watched_cbs:
                if cb not in self.__done_cbs:
                    got_a_replay = self.handleReplay(szk.CBS_NODE+"/"+cb, do_watch, be_nice,
                        singles, any_checksum)
                    if got_a_replay:
                        break            
                    else:
                        self.__done_cbs.append(cb)
        elif not got_a_replay:
            for cb in self.__done_cbs:
                got_a_replay = self.handleReplay(szk.CBS_NODE+"/"+cb, do_watch, be_nice, singles, any_checksum)
                if got_a_replay:
                    break            
 
        if not got_a_replay:
            # go looking for a new cb to watch
            #print 'look for new CB'
            self.lgr.debug('getMonitor handleCB look for new cb to watch')
            children = self.szk.zk.get_children(szk.CBS_NODE, watch)
            for cb in children:
                if self.szk.isCB(cb) and cb not in self.__watched_cbs:
                    #print 'new CB is %s' % (cb)
                    nice_locked = self.szk.isNiceLocked(szk.CBS_NODE+"/"+cb, 
                                                                szk.FORENSICS)
                    if not be_nice or not nice_locked:
                        got_a_replay = self.handleReplay(szk.CBS_NODE+"/"+cb, do_watch, 
			    be_nice, singles, any_checksum)
                        if got_a_replay:
                             # stop when we've found some action in a CB
                             break
                    else:
                       self.lgr.debug('getMonitor cb %s is nice locked' % cb)
        if got_a_replay:
            self.lgr.debug('getMonitor handleCB got a replay')
        return got_a_replay

    def getCommonName(self):
        rcb_list = []
        try:
            rcb_list = self.root.findall('rcb')
        except:
            self.lgr.error('packageManager, getCommonName, no rcb in package')
            exit(1)
        num_bins = '%02d' % len(rcb_list)
        base = rcb_list[0]
        cb_name = base.split('-')[1]
        parts = cb_name.split('_')
        cb_name = parts[0]+'_'+parts[1]
        common = 'CB'+cb_name+num_bins
        return common

    def addCFE_POV(self, cb, replay, pov_config, seed_index=0):
        if self.szk.isPoV(replay):                
            pov_config_json = None 
            if pov_config is not None:
                try:
                    pov_config_json = json.loads(pov_config)
                except:
                    print('getMonitor, addCFE could not load json %s' % pov_config)
                    exit(1)         
            pov_json, neg_json = self.defaultJsons(cb, replay, pov_config_json, seed_index)
            pov_json_element = ET.SubElement(self.doc, 'pov_json')
            pov_json_element.text = pov_json
            neg_json_element = ET.SubElement(self.doc, 'neg_json')
            neg_json_element.text = neg_json

    def addCFE(self, cb, replay, rcb_bins, rules, team_id, pov_config, seed_index=0, pov_team=None):
        '''
        append cfe-related fields to the package xml
        '''
        #team_id = self.team_sets.getTeamId(set_name)
        team_id_element = ET.SubElement(self.doc, 'team_id')
        team_id_element.text = team_id
        #rules = self.team_sets.getTeamRules(set_name)
        rules_element = ET.SubElement(self.doc, 'rules')
        rules_element.text = rules
        #rcb_bins = self.team_sets.getTeamRCBs(set_name)
        no_context_element = ET.SubElement(self.doc, 'no_context')
        no_context_element.text = 'true'
        for rcb in rcb_bins:
            cb_bin_element = ET.SubElement(self.doc, 'cb_bin')
            cb_bin_element.text = rcb 
        base = rcb_bins[0]
        cb_name = base.split('-')[1]
        parts = cb_name.split('_')
        try:
            cb_name = parts[0]+'_'+parts[1]
        except:
            print('failed to get proper parts from %s, base was %s' % (cb_name, base))
            exit(1)
        num_bins = '%02d' % len(rcb_bins)
        common = 'CB'+cb_name+num_bins
        common_element = ET.SubElement(self.doc, 'common')
        common_element.text = common
        print('call addCFE_POV')
        self.addCFE_POV(cb, replay, pov_config, seed_index)
        if pov_team is not None:
            pov_team_id_element = ET.SubElement(self.doc, 'pov_team')
            pov_team_id_element.text = pov_team

    def setChecksum(self, checksum):
        '''
        Set the configuration checksum that must match those found in any
        replay nodes, otherwise those nodes are skipped
        '''
        self.checksum = checksum

    '''
    Look for a new pov or poll under the given CB.  Returns True if one found.
    And if one found, will add the CB to the list of watched CBs if not already there.
    Will grab the nice lock on the CB if so directed.
    Hard locks are set on the pov or poll
    The package in the self.doc xml document is populated
    '''
    def handleReplay(self, cb_path, do_watch, be_nice, singles, any_checksum=False):
        got_a_replay = False 
        watch = None
        #self.lgr.debug('handleReplay for cb_path %s' % cb_path)
        if do_watch:
            watch = self.watchOneCB
        try:
            children = self.szk.zk.get_children(cb_path, watch)
        except kazoo.exceptions.NoNodeException:
            self.lgr.error('getMonitor, handleReplay, no CB node at %s' % cb_path)
            exit(1)
        cb = path.basename(cb_path)
        #if cb not in self.__done_replays:
        ''' don't reuse local copy, replay may get deleted'''
        if True:
            ''' optimization to avoid reading done nodes, e.g., after a monitor restart with a big tree '''
            value, stat = self.szk.zk.get(cb_path)
            if value is not None and len(value.strip()) > 0:
                self.__done_replays[cb] = value.strip().split(' ')
            else:
                self.__done_replays[cb] = []
        #print 'do povs for cb: %s' % cb
        if self.__package_cb is None or self.__package_cb == cb:
            for replay in children:
                replay_x_rules = replay
                if ':' in replay:
                    replay_x_rules = replay.split(':')[0]
                if (self.szk.isPoV(replay) or self.szk.isPoll(replay)) and \
                      (replay not in self.__done_replays[cb]) and \
                      (cb not in self.__watched_cbs or (replay not in self.__watched_cbs[cb])):
                    # get the replay lock.  If we get it, and this is our first go at this CB
                    # put the nice lock in the CB
                    #print 'CB child is %s' % replay
                    replay_path = cb_path+'/'+replay
                    #self.lgr.debug('getMonitor handleReplay check replay %s' % replay_path)
                    if not self.szk.isDone(replay_path):
                        replay_checksum, replay_config = self.rpm.getReplayChecksum(cb, replay)
                        if replay_config is 'debug':
                            self.lgr.debug('getMonitor handleReplay saw replay with debug configuration, should ignore')
                        if replay_config is not 'debug' and (any_checksum or replay_checksum == self.checksum) and self.szk.getHardLock(replay_path, szk.FORENSICS):
                            ''' Got the hard lock for this replay '''
                            self.lgr.debug('getMonitor handleReplay got lock for %s' % replay_path)
                            if cb not in self.__watched_cbs:
                                if be_nice:
                                    if not self.szk.getNiceLock(cb_path, szk.FORENSICS):
                                        self.lgr.debug( 'getMonitor failed to get nice lock for %s after locking %s' % \
                                             (cb, replay) )
                                if do_watch:
                                    self.__watched_cbs[cb] = []
                            if self.__package_cb is None:
                               self.__package_cb = cb
                               cb_element = ET.SubElement(self.doc, 'cb_name')
                               cb_element.text = cb
                            set_name = self.rpm.getReplaySetName(cb, replay)
                            if set_name is not None and len(set_name) > 0 and set_name.startswith('teamset'):
                                team_id = self.team_sets.getTeamId(set_name)
                                rules = self.team_sets.getTeamRules(set_name)
                                rcb_bins = self.team_sets.getTeamRCBs(set_name)
                                pov_config = self.team_sets.getPovConfig(set_name)
                                self.addCFE(cb, replay_x_rules, rcb_bins, rules, team_id, pov_config) 
                            elif set_name is not None and len(set_name) > 0:
                                team_id = 0
                                try:
                                    team_id = int(set_name)
                                except:
                                    self.lgr.error('unexpected team set value %s' % set_name)
                                    return                 
                                ''' maybe author povs vs RCBs '''
                                bin_list = self.szk.zk.get_children 
                                cb_path = szk.CBS_NODE+'/'+cb+'/config'
                                rcb_bins = self.szk.zk.get_children(cb_path)
                                self.addCFE(cb, replay_x_rules, sorted(rcb_bins), None, str(team_id), None) 
                            else:
                                self.lgr.error('no setname in %s' % replay_path)
                                return
                            if do_watch:
                                if replay not in self.__watched_cbs[cb]:
                                    self.__watched_cbs[cb].append(replay)
                            if self.szk.isPoV(replay):
                                replay_element = ET.SubElement(self.doc, 'pov')
                            else:
                                replay_element = ET.SubElement(self.doc, 'poll')
                            replay_element.text = replay_x_rules
                            self.lgr.debug('getMonitor handleReplay anychecksum, replay requested config "%s" with checksum %s' % (replay_config, replay_checksum))
                            config_element = ET.SubElement(self.doc, 'config_checksum')
                            config_element.text = replay_checksum
                            if replay_config is not None and len(replay_config) > 0:
                                config_name_element = ET.SubElement(self.doc, 'config_name')
                                config_name_element.text = replay_config
                            got_a_replay = True
                            if singles :
 	        	        # package is to contain only one replay
                                break
 
                        else:
                            #print 'failed to get hard lock for %s' % replay_path
                            pass
                if (self.szk.isPoV(replay) or self.szk.isPoll(replay)) and replay not in self.__done_replays[cb]:
                    self.__done_replays[cb].append(replay)
        return got_a_replay

    def defaultJsons(self, cb, replay, pov_config, seed_index=0):
        team_count = 1
        seed_count = 1
        print('*****************get default json for %s %s seed: %d' % (cb, replay, seed_index))
        if not replay.lower().endswith('.pov'):
            replay = replay+'.pov'
        if replay.startswith('POV') and cb.startswith('CB'):
            team_count=3
            seed_count=3
        pov_json = povJson.getPovJson(cb, "/tmp/tmpReplays/"+replay, pov_config=pov_config, 
            seed_index=seed_index, team_count=team_count, seed_count=seed_count)
        neg_json = povJson.getNegJson(cb, pov_config=pov_config, seed_index=seed_index,
            team_count=team_count, seed_count=seed_count)
        #print('neg_json: %s' % neg_json)
        #print('pov_json: %s' % pov_json)
        return pov_json, neg_json

    def buildPackageXML(self, cb, replay, replay_config, replay_checksum, rcb_bins=None, rules=None, team_id=None, 
           pov_config=None, no_timeout=False, client_id=None, client_node=None, seed_index=0, debug_cb=False, 
           debug_pov=False, pov_team=None, throw_id=None, auto_analysis=False):
        if self.doc is None:
            self.doc = ET.Element('replay_package')
        cb_element = ET.SubElement(self.doc, 'cb_name')
        cb_element.text = cb
        if self.szk.isPoV(replay):
            replay_element = ET.SubElement(self.doc, 'pov')
        else:
            replay_element = ET.SubElement(self.doc, 'poll')
        replay_element.text = replay
        config_element = ET.SubElement(self.doc, 'config_checksum')
        config_element.text = replay_checksum
        if replay_config is not None and len(replay_config) > 0:
            config_name_element = ET.SubElement(self.doc, 'config_name')
            config_name_element.text = replay_config

        if rcb_bins is not None:
            self.addCFE(cb, replay, rcb_bins, rules, team_id, pov_config, seed_index, pov_team)
        elif pov_config is not None:
            ''' special case, replaced rcb with patched reference '''
            print('Special case, addCFE_POVs for patched referen')
            self.addCFE_POV(cb, replay, pov_config, seed_index)

        if no_timeout:
            no_time_element = ET.SubElement(self.doc, 'no_timeout')
            no_time_element.text = 'TRUE'

        if debug_cb:
            debug_element = ET.SubElement(self.doc, 'debug_cb')
            debug_element.text = 'TRUE'
        elif debug_pov:
            debug_element = ET.SubElement(self.doc, 'debug_pov')
            debug_element.text = 'TRUE'

        if client_id is not None:
            client_element = ET.SubElement(self.doc, 'client')
            cid = ET.SubElement(client_element, 'client_id')
            cid.text = client_id
            cn = ET.SubElement(client_element, 'client_node')
            cn.text = client_node
        if throw_id is not None:
            throw_id_element = ET.SubElement(self.doc, 'throw_id')
            throw_id_element.text = throw_id 
        if auto_analysis:
            auto_element = ET.SubElement(self.doc, 'auto_analysis')
            auto_element.text = 'TRUE'
        retval = ET.tostring(self.doc)
        del self.doc
        self.doc = None
        return retval
  
    '''
    Get a replay package, intended for use by programs that pick up the dead, e.g., deathWatch.py
    Also used when a team set is found.  If rcb_bins exists, it is a cfe package where the names
    lack context.
    ''' 
    def getReplayPackage(self, cb_path, replay, any_config=False, set_id=None):
        retval = None
        cb = path.basename(cb_path) 
        replay_path = cb_path+'/'+replay
        if not self.szk.isDone(replay_path):
            replay_checksum, replay_config = self.rpm.getReplayChecksum(cb, replay)
            if (any_config or replay_checksum == self.checksum) and self.szk.getHardLock(replay_path, szk.FORENSICS):
                self.lgr.debug("getMonitor getReplayPackage got hardlock at %s" % replay_path)
                self.__package_cb = cb
                rcb_bins = None
                rules = None
                team_id = None
                if set_id is not None:
                    team_id = self.team_sets.getTeamId(set_id)
                    rules = self.team_sets.getTeamRules(set_id)
                    rcb_bins = self.team_sets.getTeamRCBs(set_id)
                    pov_config = self.team_sets.getPovConfig(set_id)
                retval = self.buildPackageXML(cb, replay, replay_config, replay_checksum, rcb_bins, rules, team_id, pov_config)
            elif not (any_config or replay_checksum == self.checksum):
                self.lgr.debug('getMonitor getReplayPackage, passing over replay %s %s, any_config: %r  self.cksum: %s replay cksum: %s' % (cb, replay, any_config, self.checksum, replay_checksum))
            else:
                self.lgr.debug('getMonitor getReplayPackage, failed to get hard lock at %s' % replay_path)
        else:
            self.lgr.debug('getReplayPackage, replay %s %s is done'  % (cb, replay))
        return retval
  
    def watchOneCB(self, event):
        self.lgr.debug( 'in watchOneCB, event type is %s' % str(event))
        if event is not None:
            self.__clue = path.basename(event.path)
        new_val = self.incCounter()
        if event is not None:
            self.lgr.debug('getMonitor watchOneCB counter now: %d path is %s' % (new_val, event.path))

    def watchCBs(self, event):
        '''
        callback for when a potential new replay appears.  Increment the
        counter that we wait on.
        '''
        print 'in watchCB'
        self.lgr.debug( 'in watchCBs, event path %s' % event.path)
        new_val = self.incCounter()
        if event is not None:
            self.lgr.debug('getMonitor watchCBs counter now: %d path is %s' % (new_val, event.path))

    def getPackage(self, block, be_nice, singles, timeout=None):
        '''
        Find a package.  If block is true, wait until a package is ready.
        If be_nice, then nice locks are set on CB nodes so that consumers
        can wait until a full set of PoVs have been added instead of jerking
        through the node tree.  If singles is false, then all unprocessed replays
        in a CB will be added to the packege.
        Before blindy searching the CBs tree, use the teamSets module to process
        pairs in the desired sequence.  Note that blind searching of the CBs node
        will always catch pairs missed by the teamSets serving suggestions.
        Return the package as an xml encoded string.
        '''
        done = False
        retval = None
        ''' Drones allocated to watching the debug queue do not watch team sets '''
        if not self.use_dbg_queue:
            retval = self.checkTeamSets(self.any_config)
        if retval is not None: 
            done = True
        else:
            self.doc = ET.Element('replay_package')
            self.lgr.debug('getMonitor getPackage, before the loop, use_dbg_queue is %r any_config is %r' % (self.use_dbg_queue, self.any_config))
            first_time = True
            reached_mycount = True
            got_something = False
            while not done:
                self.__package_cb = None
                self.lgr.debug( 'getMonitor getPackage do readCounter')
                mycount = self.readCounter()
                self.lgr.debug( 'getMonitor getPackage back from readCounter')
                if block and not got_something and not first_time:
                    self.lgr.debug( 'getMonitor getPackage call waitCounter, mycount of %d' % mycount)
                    reached_mycount = self.waitCounter(mycount, timeout)
                    self.lgr.debug( 'getMonitor getPackage back from waitCounter')
                if not self.use_dbg_queue and not self.any_config:
                    self.lgr.debug( 'getMonitor getPackage not using debug queue and not any_config, call handleCB')
                    got_something = self.handleCB(block, be_nice, False, singles)
                    if not got_something and len(self.__done_cbs) > 0:
                        # we skipped some CBs, go back and look at those before sleeping
                        self.lgr.debug( 'getMonitor nothing new, go back to what we already saw')
                        got_something = self.handleCB(block, be_nice, True, singles)
                        self.__done_cbs = []
                if not got_something and self.use_dbg_queue:
                    retval = self.dbg_queue.getReplay(self.watchCBs, self.only_client)
                    if retval is not None:
                        done = True
                    self.lgr.debug('getMonitor getPackage tried debug, got something?: %r' % done)
                if not self.use_dbg_queue and not done and not got_something:
                    self.lgr.debug('getMonitor getPackage, try using any checksum')
                    got_something = self.handleCB(block, be_nice, False, singles, True)
                    if got_something:
                        self.lgr.debug('getMonitor getPackage, got something using any checksum')
                done = done or not block or got_something or not reached_mycount
                first_time = False
            if got_something:
                # NOTE not entered if dbg_queue used.  restructure for clarity
                retval = ET.tostring(self.doc)
        del self.doc
        self.doc = None
        return retval

    def checkTeamSets(self, any_config):
        '''
        Use the teamSets module to get a CB/replay pair from the team sets. Package
        the pair in an xml string and return it.
        '''
        done = False
        retval = None
        self.lgr.debug('checkTeamSets for next team set entry')
        while not done:
            cb, replay, set_id = self.team_sets.getNextTeamSet()
            if cb is not None:
                # got a team set. 
                self.lgr.debug('checkTeamSets got cb %s replay %s' % (cb, replay))
                cb_path = szk.CBS_NODE + '/' + cb
                replay_path = cb_path+'/'+replay
                self.lgr.debug('checkTeamSets, is there a replay for '+replay_path)
                stat = None
                try:
                    stat = self.szk.zk.exists(replay_path)
                except kazoo.exceptions.NoNodeException:
                    pass
                if stat is not None:
                    retval = self.getReplayPackage(cb_path, replay, any_config=any_config, set_id = set_id)
                    if retval is not None:
                        done = True
                    else:
                        # replay entry exists, but failed to get lock, someone else must be working on it, try next one
                        self.lgr.debug('checkTeamSets failed to get hard lock for cb %s replay %s, try next' % (cb, replay))
                else:
                    # we got to the CBs hieararchy before the CB or/and replay was created, fallback to watcher
                    self.lgr.debug('checkTeamSets, team set entry before replay created? %s' % replay_path)
                    done = True

            else:
                # no team sets, we must be done
                done = True
        return retval

 
