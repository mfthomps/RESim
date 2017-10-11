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
import kazoo
import cbConfig
import os
import json
import teamSets
import utils
import logging
import updateMasterCfg
class replayMgr():
    '''
    Add replays to the zookeeper node hierarchy
    and record when replays have completed.
    '''
    def __init__(self, szk, cfg, lgr=None):
        self.zk = szk
        self.cfg = cfg
        self.lgr = lgr
        if lgr is None:
            self.lgr = logging
            print('replayMgr using plain logging')
            self.lgr.debug('replayMgr using plain logging')
        else:
            print('replayMgr using given lgr')
        self.lgr.debug('replayMgr init')
        self.team_sets = teamSets.teamSets(szk, self.lgr)
        self.lgr.debug('replayMgr back from teamSets init')

    def putReplay(self, cb, replay, be_nice, queue_name, checksum, set_name='', config='master', replace=False, rules=None):
        '''
        Put a POV (or Poll) node and set a nice lock on the CB if it is created.  
        If a CB node is created, write the CB's configuration (elf sections) into CONFIG nodes off the CB node
        Return whether the node is created (i.e., did not already exist, and if a nice lock was grabbed).
        '''
        got_nice = False
        created_replay = True
        created_cb = False
        #path_name = utils.rmBinNumFromName(cb)
        cb_path = szk.CBS_NODE+"/"+cb
        replay_path = cb_path+"/"+replay
        if rules is not None and len(rules.strip())>0:
            replay_path += ':%s' % rules
        if self.zk.zk.exists(replay_path):
            return False, False
	#print 'creating path %s' % replay_path
        nice_lock = False
        try:
            self.zk.zk.create(cb_path, '', None, makepath=True) 
            created_cb = True
            print 'putReplay write configuruation node info for cb %s path %s' % (cb, cb_path)
            self.lgr.debug("create cb configuration file at %s for cb %s" % (cb_path, cb))
            self.multiBinaryCB(cb_path, cb)
        except kazoo.exceptions.NodeExistsError:
            pass

        if created_cb and be_nice:
            print 'try getting nice lock for %s' % cb_path
            self.zk.getNiceLock(cb_path, queue_name)
            got_nice = True
           
        j_string = json.dumps((checksum, set_name, config))
        try:
            self.zk.zk.create(replay_path, j_string, None, makepath=True) 
            self.lgr.debug("replayMgr, create replay at %s, json of %s" % (replay_path, j_string))
            print("replayMgr, create replay at %s, json of %s" % (replay_path, j_string))
        except kazoo.exceptions.NodeExistsError:
            if replace:
                self.zk.zk.set(replay_path, j_string)
                self.lgr.debug('putReplay replaced replay at %s' % replay_path)
            else:
                print 'in putReplay, already exists: %s' % replay_path
                self.lgr.debug('replayMgr putReplay, already exists: %s' % replay_path)
                created_replay = False
        return created_replay, got_nice

    def getBinConfigs(self, cb_path, binaries):
        self.lgr.debug('replayMgr, in getBinConfigs cb_path %s  cb %s' % (cb_path, binaries[0]))
        for binary in binaries:
            config_path = cb_path+'/'+szk.CONFIG+'/'+os.path.basename(binary)
            try:
                self.zk.zk.create(config_path, '', None, makepath=True) 
            except kazoo.exceptions.NodeExistsError:
                 self.lgr.debug('replayMgr, getBinConfigs node %s already exists' % config_path)
            config = cbConfig.cbConfig(binary)
            if config is not None:
                self.lgr.debug('replayMgr, set config for %s to %s' % (config_path, config))
                self.zk.zk.set(config_path, config)
            else:
                self.lgr.error('replayMgr, could not get config for %s, binary: %s' % (config_path, binary))

    def showBinConfigs(self, cb_path, binaries):
        self.lgr.debug('replayMgr, in showBinConfigs cb_path %s  cb %s' % (cb_path, binaries[0]))
        for binary in binaries:
            config_path = cb_path+'/'+szk.CONFIG+'/'+os.path.basename(binary)
            print('show config for %s ' % (config_path))
            value = self.zk.zk.get(config_path)
            print value
        

    def multiBinaryCB(self, cb_path, cb):
        '''
        Create configuration (cgc section headers) for one or more
        binaries within a CB service
        TBD: this must be revised when the real repository is established.  Specifically, the
        logic that determines if there are multiple binaries in a CB.
        '''
        self.lgr.debug('in multiBinaryCB cb_path %s  cb %s' % (cb_path, cb))
        cb_file_path = self.zk.pathFromName(self.cfg.cb_dir, cb)
        if cb_file_path is None:
            self.lgr.error('multiBinaryCB no path found for %s' % cb)
            return
        csid = utils.getCSID(cb)
        num_bins = utils.numBins(csid)
        if num_bins == 1:
            self.lgr.debug('replayMgr, multiBinaryCB just one bin cb_file_path is '+cb_file_path)
            ''' just one CB '''
            config_path = cb_path+'/'+szk.CONFIG+'/'+cb+'_01'
            try:
                self.zk.zk.create(config_path, '', None, makepath=True) 
            except kazoo.exceptions.NodeExistsError:
                 self.lgr.debug('multiBinaryCB node %s already exists' % config_path)
            config = cbConfig.cbConfig(cb_file_path+'_01')
            if config is not None:
                self.lgr.debug('set config for %s to %s' % (config_path, config))
                self.zk.zk.set(config_path, config)
            else:
                self.lgr.error('replayMgr, multiBinaryCB could not get config for %s' % config_path)
            #print 'created the cb %s' % cb_path
        else:
            ''' multple binaries '''
            done = False
            for i in range(1, num_bins+1):
                suffix = '_%02x' % i
                full_file = cb_file_path+suffix 
                self.lgr.debug( 'replayMgr, multiBinaryCB look for %s' % full_file)
                if os.path.isfile(full_file):
                    config_path = cb_path+'/'+szk.CONFIG+'/'+cb+suffix
                    try:
                        self.zk.zk.create(config_path, '', None, makepath=True) 
                    except kazoo.exceptions.NodeExistsError:
                        self.lgr.debug('multiBinaryCB node %s already exists' % config_path)
                    
                    config = cbConfig.cbConfig(full_file)
                    if config is not None:
                        self.lgr.debug( 'set multi config for %s to %s' % (config_path, config))
                        self.zk.zk.set(config_path, config)
                        i += 1
                    else:
                        self.lgr.error('replayMgr, multibinary, no config for %s' % full_file)
                else:
                    done = True

    def multiConfig(self, cb_path, cb):
        '''
        '''
        self.lgr.debug('in multiConfig cb_path %s  cb %s' % (cb_path, cb))
        cb_file_path = self.zk.pathFromName(self.cfg.cb_dir, cb)
        if cb_file_path is None:
            self.lgr.error('multiConfig no path found for %s' % cb)
            return
        csid = utils.getCSID(cb)
        num_bins = utils.numBins(csid)
        if num_bins == 1:
            self.lgr.debug('multiConfig, multiConfig just one bin cb_file_path is '+cb_file_path)
            ''' just one CB '''
            config_path = cb_path+'/'+szk.CONFIG+'/'+cb+'_01'
            print('get config for %s ' % (config_path))
            value = self.zk.zk.get(config_path)
            print value
        else:
            ''' multple binaries '''
            done = False
            for i in range(1, num_bins+1):
                suffix = '_%02x' % i
                config_path = cb_path+'/'+szk.CONFIG+'/'+cb+suffix
                print( 'get multi config for %s ' % (config_path))
                value=self.zk.zk.get(config_path)
                print value
                i += 1
                
    def recordReplayDoneHint(self, cb_name, replay, rules=None):
        '''
        Add to list of replays that are done for this CB.  Intended for use by  by
        getMonitor to avoid reading nodes that are done. Am I a POM? 
        '''
        path = szk.CBS_NODE+'/'+cb_name
        done = False
        if rules is not None and len(rules.strip())>0:
            replay+=':%s' % rules
        while not done:
            try:
                try:
                    value, stat = self.zk.zk.get(path)
                except kazoo.exceptions.NoNodeError:
                    self.lgr.error('replayMgr recordReplayDoneHint found CB node missing, fatal. %s' % path)
                    exit(1)
                if replay not in value:
                    value = value+' '+replay
                try:
                    bs = value.encode('latin-1')
                    self.zk.zk.set(path, bs, version=stat.version)
                    done = True
                except kazoo.exceptions.BadVersionError:
                    self.lgr.debug('replayMgr, recordReplayDoneHint, collision on update, retry')
            except kazoo.exceptions.ConnectionLoss:
                self.lgr.debug('replayMgr, recordReplayDoneHint, connection loss, reconnect')
                self.zk.reconnect()

    def fixCache(self):
        cb_list = self.zk.zk.get_children(szk.CBS_NODE)
        for cb in cb_list:
            path = szk.CBS_NODE+'/'+cb
            try:
                self.zk.zk.set(path, '')
            except kazoo.exceptions.BadVersionError:
                pass
            replay_list = self.zk.zk.get_children(path)
            for replay in replay_list:
                if self.isReplayDone(cb, replay):
                    #print('record for %s %s' % (cb, replay))
                    self.recordReplayDoneHint(cb, replay)    


    def isReplay(self, cb_name, replay, rules=None):
        if rules is not None and len(rules.strip())>0:
           replay += ':%s' % rules
        retval = False
        path = szk.CBS_NODE+'/'+cb_name+'/'+replay
        try:
            if self.zk.zk.exists(path):
                retval = True
        except kazoo.exceptions.ConnectionLoss:
            self.lgr.debug('isReplay, connection loss, reconnect')
            self.zk.reconnect()
            if self.zk.zk.exists(path):
                retval = True
        return retval

    def isReplayDone(self, cb_name, replay, rules=None):
        retval = False
        if rules is not None and len(rules.strip())>0:
           replay+=':%s' % rules
        path = szk.CBS_NODE+'/'+cb_name+'/'+replay+'/'+szk.DONE
        try:
            if self.zk.zk.exists(path):
                retval = True
        except kazoo.exceptions.ConnectionLoss:
            self.lgr.debug('isReplayDone, connection loss, reconnect')
            self.zk.reconnect()
            if self.zk.zk.exists(path):
                retval = True
        return retval

    def replayDone(self, cb_name, replay, log, rules=None):
        ''' 
        Indicate that the monitoring of a PoV or Poll has completed, and store the summary
        log of its events in the zk node 
        If the replay was already done, the log is appended to the previous log
        '''
        if rules is not None and len(rules.strip())>0:
            rules = os.path.basename(rules)
            replay+=':%s' % rules
        retval = False
        bs = log.encode('latin-1')
        if cb_name is None or replay is None:
            print 'cannot mark replay done, missing a name cb: %s  replay: %s' % (cb_name, replay)
            self.lgr.debug('cannot mark replay done, missing a name cb: %s  replay: %s' % (cb_name, replay))
            return retval
        path = szk.CBS_NODE+'/'+cb_name+'/'+replay+'/'+szk.DONE
        print 'creating path at %s' % path
        value = ''
        try:
            value = '<replay_log>'+bs+'</replay_log>'
            self.zk.zk.create(path, value, None, makepath=True) 
            self.lgr.debug('replayDone, adding log to new node %s %s' % (path, value))
            print value
        except kazoo.exceptions.NodeExistsError:
            self.lgr.debug('replayDone, adding log to existing node %s, %s' % (path, value))
            value, stat = self.zk.zk.get(path)
            stripped = self.zk.stripLogTail(value)
            value = stripped + '\n'+bs+'</replay_log>'
            self.zk.zk.set(path, value)
        except kazoo.exceptions.ConnectionLoss:
            self.lgr.debug('replayMgr, replayDone, connection loss, reconnect')
            self.zk.reconnect()
        except:
            self.lgr.debug('wtf, over?')
            self.zk.reconnect()
        #except kazoo.exceptions.NoNodeError:
        #    print('replayDone error creating node at %s, missing node in path' % path)
        #    self.lgr.debug('replayDone error creating node at %s, missing node in path' % path)
        #    #raise kazoo.exceptions.NoNodeError
        #    return False
        set_name = self.getReplaySetName(cb_name, replay)
        if set_name is not None and len(set_name.strip()) > 0 and set_name.startswith('teamset'):
            retval = self.team_sets.checkCompetitorSet(cb_name, replay, log, set_name)
        self.recordReplayDoneHint(cb_name, replay)
        return retval

    def rmReplay(self, cb, replay, rules=None):
        if rules is not None and len(rules.strip())>0:
            replay+=':%s' % rules
        self.lgr.debug('rmReplay')
        cb_path = szk.CBS_NODE+"/"+cb
        value, stat = self.zk.zk.get(cb_path)
        if replay in value:
            hint_list = value.replace(replay,'')
            bs = hint_list.encode('latin-1')
            self.zk.zk.set(cb_path, bs)
        else:
            self.lgr.debug('replayMgr rmReplay, replay not in hints: %s %s' % (cb, replay))
        replay_path = cb_path+"/"+replay
        try:
            self.zk.zk.delete(replay_path, -1, recursive=True)
        except kazoo.exceptions.NotEmptyError:
            self.lgr.error('could not delete %s, not empty' % replay_path)
            exit(1)
        self.lgr.debug('replayMgr rmReplay removed node %s' % replay_path)

    def rmReplayDone(self, cb, replay, rules=None):
         if rules is not None and len(rules.strip())>0:
            replay+=':%s' % rules
         path = szk.CBS_NODE+'/'+cb+'/'+replay+'/'+szk.DONE
         try:
             self.zk.zk.delete(path)
         except:
             self.lgr.error('replayMgr, rmReplayDone, no node?  %s' % path)

    def rmReplayLock(self, cb, replay):
         replay_path = szk.CBS_NODE+'/'+cb+'/'+replay
         path = self.zk.getLockPath(replay_path, szk.FORENSICS)
         try:
             self.zk.zk.delete(path)
         except:
             self.lgr.error('replayMgr, rmReplayLock, no node?  %s' % path)

    def rmIncompleteReplays(self):
        cbs = self.zk.getCBs()
        num_removed = 0
        for cb in cbs:
            replays = self.zk.getReplays(cb)
            for replay in replays:
                if self.zk.isPoV(replay) or self.zk.isPoll(replay):
                    if not self.zk.isReplayDone(cb, replay):
                        self.rmReplay(cb, replay)
                        print('removed replay: %s : %s' % (cb, replay))
                        num_removed += 1
        print('%d replays were removed' % num_removed)

    def updateReplayConfig(self, config_name):
        umc =  updateMasterCfg.updateMasterCfg(self.zk, self.cfg, self.lgr)
        config_node, dum = self.zk.nodeFromConfigName(config_name)
        checksum = umc.getChecksum(config_node)
        if checksum is None:
            print('could not get checksum for config %s, node %s' % (config_name, config_node))
            exit(1)
        print('will updated incomplete replays to use config w/ checksum %s' % checksum)
        cbs = self.zk.getCBs()
        num_updated = 0
        for cb in cbs:
            cb_path = szk.CBS_NODE+"/"+cb
            replays = self.zk.getReplays(cb)
            for replay in replays:
                if self.zk.isPoV(replay) or self.zk.isPoll(replay):
                    if not self.zk.isReplayDone(cb, replay):
                        replay_path = cb_path+"/"+replay
                        value, stat = self.zk.zk.get(replay_path)
                        #j_string = json.dumps((checksum, set_name, config))
                        decoded = json.loads(value)
                        j_string = json.dumps((checksum, decoded[1], decoded[2]))
                        self.zk.zk.set(replay_path, j_string)
                        print('updated config of replay: %s : %s' % (cb, replay))
                        num_updated += 1
        print('%d replays were updated' % num_updated)

    def rmAllReplays(self):
        cbs = self.zk.getCBs()
        num_removed = 0
        for cb in cbs:
            replays = self.zk.getReplays(cb)
            for replay in replays:
                if self.zk.isPoV(replay) or self.zk.isPoll(replay):
                    self.rmReplay(cb, replay)
                    print('removed replay: %s : %s' % (cb, replay))
                    num_removed += 1
            cb_path = szk.CBS_NODE+"/"+cb
            self.zk.zk.set(cb_path,'')
            print('cleared replays in %s' % cb_path)
        print('%d replays were removed' % num_removed)

    def rmAuthPOVs(self):
        cbs = self.zk.getCBs()
        num_removed = 0
        for cb in cbs:
            replays = self.zk.getReplays(cb)
            for replay in replays:
                if self.zk.isPoV(replay) and replay.startswith('POV'):
                    self.rmReplay(cb, replay)
                    print('removed replay: %s : %s' % (cb, replay))
                    num_removed += 1
        print('%d replays were removed' % num_removed)

    def isLogged(self, cb, replay):
        logged_path = szk.CBS_NODE+"/"+cb+"/"+replay+"/logged"
        try:
            if self.zk.zk.exists(logged_path):
                return True
            else:
                return False
        except kazoo.exceptions.NoNodeError:
            self.lgr.debug('replayMgr, isLogged called, but missing node for %s' % logged_path)
            return False

    def getLogged(self, cb):
        '''
        Return list of replays for the given cb that are marked as being logged
        '''
        cb_path = szk.CBS_NODE+"/"+cb
        replays = self.zk.getReplays(cb)
        logged = []
        for replay in replays:
            if self.zk.isPoV(replay) or self.zk.isPoll(replay):
                logged_path = cb_path+"/"+replay+'/logged'
                if self.zk.zk.exists(logged_path):
                    logged.append(replay)
        return logged


    def clearLogged(self, cb, replay):
        cb_path = szk.CBS_NODE+"/"+cb
        replay_path = cb_path+"/"+replay
        try:
            self.zk.zk.delete(replay_path+'/logged')
        except kazoo.exceptions.NoNodeError:
            pass

    def clearAllLogged(self):
        cbs = self.zk.getCBs()
        num_removed = 0
        for cb in cbs:
            cb_path = szk.CBS_NODE+"/"+cb
            replays = self.zk.getReplays(cb)
            for replay in replays:
                if self.zk.isPoV(replay) or self.zk.isPoll(replay):
                    replay_path = cb_path+"/"+replay
                    try:
                        self.zk.zk.delete(replay_path+'/logged')
                        num_removed += 1
                    except kazoo.exceptions.NoNodeError:
                        pass
        print('clearAllLogged removed %d log flags' % (num_removed))

    def clearAllAuthPOVsLogged(self):
        cbs = self.zk.getCBs()
        num_removed = 0
        for cb in cbs:
            cb_path = szk.CBS_NODE+"/"+cb
            replays = self.zk.getReplays(cb)
            for replay in replays:
                if replay.startswith('POV'):
                    replay_path = cb_path+"/"+replay
                    try:
                        self.zk.zk.delete(replay_path+'/logged')
                        num_removed += 1
                    except kazoo.exceptions.NoNodeError:
                        pass
                        print('not logged: %s' % replay_path)
        print('clearAllAuthPOVsLogged removed %d log flags' % (num_removed))
                 
    def delReplay(self, cb, replay):
        cb_path = szk.CBS_NODE+"/"+cb
        replay_path = cb_path+"/"+replay
        try:
            self.zk.zk.delete(replay_path, recursive=True)
        except kazoo.exceptions.NoNodeError:
            pass

    def getReplayChecksum(self, cb, replay):
        '''
        Return the checksum and configuration name read from the replay node
        j_string = json.dumps((checksum, set_name, config))
        '''
        retval = None
        cb_path = szk.CBS_NODE+"/"+cb
        replay_path = cb_path+"/"+replay
        value, stat = self.zk.zk.get(replay_path)
        try:
            decoded = json.loads(value)
        except:
            self.lgr.error('replayMgr, getReplayChecksum could not decode %s from %s' % (value, replay_path))
            return None, None
        return decoded[0], decoded[2]

    def getReplaySetName(self, cb, replay):
        '''
        Return the set name read from a replay node 
        '''
        retval = None
        cb_path = szk.CBS_NODE+"/"+cb
        replay_path = cb_path+"/"+replay
        value, stat = self.zk.zk.get(replay_path)
        if value is not None and len(value)>0:
            try:
                decoded = json.loads(value)
            except:
                self.lgr.error('replayMgr, getReplaySetName could not decode %s from %s' % (value, replay_path))
                return None
            retval = decoded[1]
        return retval

    def startDebug(self, replay):
        self.lgr.debug("replayMgr, startDDebug %s" % replay)
        try:
            result = self.zk.zk.create(self.zk.OUR_DEBUG_STATUS, value=replay, ephemeral=True, makepath=True)
        except:
            self.lgr.debug("replayMgr, startDebug failed create of %s" % self.zk.OUR_DEBUG_STATUS)

    def doneDebug(self, replay):
        self.lgr.debug("replayMgr, doneDebug %s" % replay)
        try:
            result = self.zk.zk.delete(self.zk.OUR_DEBUG_STATUS)
        except:
            self.lgr.debug("replayMgr, doneDebug failed delete of %s" % self.zk.OUR_DEBUG_STATUS)

    def checkDebugWait(self, callback):
        '''
        Return true if node exists indicating debug session still in progress
        '''
        result = False
        try:
            result = self.zk.zk.exists(self.zk.OUR_DEBUG_STATUS, callback)
        except:
            self.lgr.error("replayMgr, checkDebugWait failed exists of %s" % self.zk.OUR_DEBUG_STATUS)
        return result
