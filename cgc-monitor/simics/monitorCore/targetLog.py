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

import time
import datetime
import xml.etree.ElementTree as ET
import json
import kazoo
import os
from monitorLibs import szk
from monitorLibs import replayMgr
from monitorLibs import utils
from monitorLibs import throwMgr
from monitorLibs import forensicEvents
'''
Prepare log entries for monitored events.
TBD split up by pid?
'''
class targetLog():
    def __init__(self, top, szk, cfg, master_cfg, sys_config, lgr):
        self.szk = szk
        pg_vet = None
        self.lgr = lgr
        self.lgr.debug('targetLog init')
        self.rpm = replayMgr.replayMgr(szk, cfg, lgr=self.lgr)
        self.cb_name = {}
        self.replay_name = {}
        self.previous_replay_name = {}
        self.previous_cb_name = {}
        self.doc = {}
        self.ts = {}
        self.needed_items = {}
        self.done_items = {}
        self.done_pids = {}
        self.num_cbs = {}
        self.expected_cbs = {}
        self.top = top
        self.master_cfg = master_cfg
        self.cfg = cfg
        self.debug_event = {}
        self.sys_config = sys_config
        # not used yet
        self.throw_mgr = throwMgr.throwMgr(szk, lgr)
        self.protected_access = {}
        self.seed_lookup = {}
        self.last_cb_seed = None
        self.hacked_cb_name = None
        # TBD index by seed for concurrent polls!
        self.rules = None

    ''' start a new replay element, but only if one has not yet been started '''
    def startReplay(self, seed):
        self.lgr.debug('targetLog, startReplay for seed %s' % seed)
        if seed not in self.doc:
            self.lgr.debug('targetLog, startReplay create new document for seed <%s>' % seed)
            self.doc[seed] = ET.Element('replay_entry')
            config_checksum = ET.SubElement(self.doc[seed], 'config_checksum')
            config_checksum.text = self.master_cfg.checksum

    def findCBName(self, seed):
        entries = self.doc[seed].findall('cb_entry')
        for entry in entries:
            cb_name = entry.findtext("cb_name")
            return cb_name
        return None

    def findCB(self, cb, seed):
        entries = self.doc[seed].findall('cb_entry')
        for entry in entries:
            cb_name = entry.findtext("cb_name")
            if cb_name == cb:
                return entry
        return None

    def addSeed(self, pid, cell_name, seed):
        name = str(pid)+':'+cell_name
        self.seed_lookup[name] = seed
        self.lgr.debug('targetLog addSeed %s : %s' % (name, seed))

    def findSeed(self, pid, cell_name):
        name = str(pid)+':'+cell_name
        if name in self.seed_lookup:
            return self.seed_lookup[name]
        else:
            self.lgr.error('targetLog findSeed, could not find %s ' % (name))
            return None

    def findPidServerFromSeed(self, seed):
        for name in self.seed_lookup:
            if self.seed_lookup[name] == seed:
                pid_str, server =  name.split(':') 
                return int(pid_str), server
        return None, None

    def newPair(self, common, watchPlayer, pid, cell_name):
        seed = findSeed(pid, cell_name)
        if seed in self.cb_name:
            self.lgr.debug('targetLog, newPair called but prior cb not closed out %s' % self.cb_name[seed])
            return False
        self.cb_name[seed] = common
        self.num_cbs[seed] = 0
        #self.needed_items = utils.numBins(common)
        self.needed_items[seed] = 0
        self.done_items[seed] = 0
        self.expected_cbs[seed] = self.needed_items[seed]
        if watchPlayer:
            self.needed_items[seed] += 1
        self.lgr.debug('targetLog, newPair new replay pair %s, needed items is %d, done items: %d' % (common, self.needed_items[seed], self.done_items[seed]))
        self.debug_event[seed] = False
        self.protected_access[seed] = []
        return True

    def swapSeed(self, old_seed, new_seed):
      self.lgr.debug('targetLog swapSeed old: %s new: %s' % (old_seed, new_seed))
      for pair in self.seed_lookup:
          if self.seed_lookup[pair] == old_seed:
              self.seed_lookup[pair] = new_seed
              break
      try:
        self.needed_items[new_seed] = self.needed_items.pop(old_seed)
      except: 
        pass
      try:
        self.done_items[new_seed] = self.done_items.pop(old_seed)
      except: 
        pass
      try:
        self.debug_event[new_seed] = self.debug_event.pop(old_seed)
      except: 
        pass
      try:
        self.num_cbs[new_seed] = self.num_cbs.pop(old_seed)
      except: 
        pass
      try:
        self.expected_cbs[new_seed] = self.expected_cbs.pop(old_seed)
      except: 
        pass
      try:
        self.doc[new_seed] = self.doc.pop(old_seed)
      except: 
        pass
      try:
        self.cb_name[new_seed] = self.cb_name.pop(old_seed)
      except: 
        pass
      try:
        self.replay_name[new_seed] = self.replay_name.pop(old_seed)
      except: 
        pass
      try:
        self.previous_replay_name[new_seed] = self.previous_replay_name.pop(old_seed)
      except: 
        pass
      try:
        self.protected_access[new_seed] = self.protected_access.pop(old_seed)
      except: 
        pass
      try:
        self.ts[new_seed] = self.ts.pop(old_seed)
      except: 
        pass
       

    def initCounters(self, seed):
        if seed not in self.needed_items:
            self.needed_items[seed] = 0
        if seed not in self.done_items:
            self.done_items[seed] = 0
        if seed not in self.debug_event:
            self.debug_event[seed] = False
        if seed not in self.num_cbs:
            self.num_cbs[seed] = 0
        if seed not in self.expected_cbs:
            self.expected_cbs[seed] = 0

    
    def cfeRcbMatch(self, name1, name2):
        ''' TBD will fail if running multiple sessions & same multibin CB comes up '''
        if '-' in name1:
            parts1 = name1.split('-')
            parts2 = name2.split('-')
            if parts1[0] != parts2[0]:
                    return False
            cb_name1 = parts1[1]
            cb_name2 = parts1[1]
        else:
            cb_name1 = name1
            cb_name2 = name2
        
        base1_parts = cb_name1.split('_')
        base2_parts = cb_name2.split('_')
        self.lgr.debug('base1: %s base2: %s' % (str(base1_parts), str(base2_parts)))
        if len(base1_parts) < 2 or len(base2_parts) < 2:
            return False
        for i in range(2):
            if base1_parts[i] != base2_parts[i]:
                return False
        return True

    def newCB(self, name, watchPlayer, seed, pid, cell_name, rules):
        '''
        exec of a new CB detected, could be one of many within same set
        '''
        retval = True
        #if self.needed_items == 0:
        self.addSeed(pid, cell_name, seed)
        self.initCounters(seed)
        self.last_cb_seed = seed
        # TBD hack, use CB seed for polls if they just started
        self.swapSeed('some_poller', seed)
        if self.cfg.cfe and seed not in self.cb_name:
            ''' first instance of a binary for this cb '''
            if name.startswith('CB'):
                self.cb_name[seed] = utils.getCommonName(name)
            else:
                ''' no-context CFE cb name '''
                no_bin = utils.rmBinNumFromName(name)
                self.cb_name[seed] = no_bin
            self.needed_items[seed] = self.needed_items[seed] + 1
            self.protected_access[seed] = []
            #self.needed_items = self.needed_items + utils.numBins(self.cb_name)
        else:
            # replay runs cb and player as pairs
            if seed not in self.cb_name:
                self.lgr.critical('newCB called before newPair, name is %s' % name)
                return False
            else:
                if not self.cfg.cfe:
                    common = utils.getCommonName(name)
                    if common != self.cb_name[seed]:
                        self.lgr.critical('targetLog newCB called for cb %s while still processing %s' % (name, self.cb_name[seed]))
                        return False
                    else:
                        self.needed_items[seed] = self.needed_items[seed] + 1
                else:
                    if not self.cfeRcbMatch(self.cb_name[seed], name):
                        self.lgr.critical('targetLog newCB cfe called for cb %s while still processing %s' % (name, self.cb_name[seed]))
                        return False
                    else:
                        #if utils.getBinNumFromName(name) == '1': 
                        #    self.cb_name[seed] = utils.rmBinNumFromName(name)
                        self.needed_items[seed] = self.needed_items[seed] + 1
                    
        self.startReplay(seed)
        entry = ET.SubElement(self.doc[seed], 'cb_entry')
        cb = ET.SubElement(entry, 'cb_name')
        cb.text = name
        self.lgr.debug('targetLog new CB %s needed_items %d' % (name, self.needed_items[seed]));
        if seed not in self.num_cbs:
            self.num_cbs[seed] = 0
        self.num_cbs[seed] += 1
        if rules is not None:
            rules_element = ET.SubElement(self.doc[seed], 'rules')
            rules_element.text = self.rules
        return retval

    def newReplay(self, name, watch_player = False, debug_binary = False, seed = 'some_poller', pid=None, cell_name=None):
        ''' 
        Called when a new replay is detected. 
        Make no assumptions about ordering of CB launch and PoV launch!
        *** on the contrary, assume cfe polls start befor the CB, and PoVs start after the CB
        '''
        self.lgr.debug('targetLog newReplay %s watch_player %r is pov %r  seed: %s' % (name, watch_player, self.top.isPoVcb(name), seed))
        if seed != 'some_poller':
            ''' HACK, TBD will not work if multiple pollers/povers at same time '''
            seed = self.last_cb_seed

        if pid is not None:
            self.addSeed(pid, cell_name, seed)

        self.initCounters(seed)
        if self.top.isPoVcb(name):
            if self.cfg.cfe and (watch_player or debug_binary):
                self.needed_items[seed] += 1
            #name  = os.path.splitext(name)[0]
        self.replay_name[seed] = name
        self.previous_replay_name[seed] = None
        self.startReplay(seed)
        self.ts[seed] = time.time()
        st = datetime.datetime.fromtimestamp(self.ts[seed]).strftime('%Y-%m-%d %H:%M:%S')
        replay = ET.SubElement(self.doc[seed], 'replay_name')
        replay.text = name
        if not self.cfg.cfe:
            common = ET.SubElement(self.doc[seed], 'common_name')
            common.text = self.cb_name[seed]
        start = ET.SubElement(self.doc[seed], 'time_start')
        start.text = st
        sys_config = ET.SubElement(self.doc[seed], 'sys_config')
        sys_config.text = self.sys_config
        self.lgr.debug('targetLog newReplay %s on config %s needed_items is %d' % (name, self.sys_config, self.needed_items[seed]));
        if debug_binary:
            self.rpm.startDebug(name)
        return seed
    

    def getEntry(self, seed, delete = False):
        self.lgr.debug('targetLog, getEntry for seed %s' % seed)
        retval = ''
        if seed in self.doc:
            if self.rules is not None:
                rules = self.doc[seed].find('rules')
                if rules is None:
                    self.lgr.debug('targetLogs getEntry adding rules')
                    rules_element = ET.SubElement(self.doc[seed], 'rules')
                    rules_element.text = self.rules
                
            retval = ET.tostring(self.doc[seed])
            if delete:
                self.doc.pop(seed, None)
                self.cb_name.pop(seed, None)
                self.replay_name.pop(seed, None)
        return retval

    def appendLog(self, tag, value, comm, pid, cell_name):
        seed = self.findSeed(pid, cell_name)
        retval = True
        if self.top.isCB(comm):
            self.appendCB(tag, value, comm, seed)
        else: 
            if seed in self.doc:
                element = ET.SubElement(self.doc[seed], tag)
                element.text = '%s' % value
            else:
                self.lgr.debug('logging %s, but no current doc' % tag)
                retval = False
        return retval

    def appendCB(self, tag, value, cb, seed):
        if seed in self.doc:
            entry = self.findCB(cb, seed)
            if entry is not None:
                element = ET.SubElement(entry, tag)
                element.text = '%s' % value
            else:
                self.lgr.debug('logging %s for cb %s, but no current cb with seed %s' % (tag, cb, seed))
        else:
            self.lgr.debug('logging %s for cb %s, but no current doc for seed %s' % (tag, cb, seed))
        
        pass

    def resetState(self, seed):
        self.lgr.debug('targetLog resetState for seed %s' % seed)
        self.done_items.pop(seed, None)
        self.needed_items.pop(seed, None)
        self.cb_name.pop(seed, None)
        self.replay_name.pop(seed, None)
        if seed in self.previous_replay_name:
            self.previous_replay_name.pop(seed, None)
        if seed in self.expected_cbs:
            self.expected_cbs.pop(seed, None)
        if seed in self.debug_event:
            self.debug_event.pop(seed, None)
        if seed in self.ts:
            self.ts.pop(seed, None)
        self.seed_lookup.pop(seed, None)
        self.hacked_cb_name = None
        self.rules = None

    def getLatestPOV(self):
        ''' only intended for use if needed before the pov starts executing, not always reliable '''
        package = self.szk.getLatestLocalPackage(self.lgr)
        if package is None:
            self.lgr.debug('launcherExitsNoReplay, no package')
            return
        pov = package.find('pov')
        if pov is not None:
            return pov.text
        else:
            return None

    def launcherExitsNoReplay(self, cell_name, pid, comm):
        self.lgr.error('launcher exited without a replay on %s' % cell_name)
        pov = self.getLatestPOV(self)
        if pov is not None:
            self.lgr.debug('will mark %s %s as done' % (self.hacked_cb_name, pov))
            try:
                doc = ET.Element('replay_entry')
                element = ET.SubElement(doc, 'launcher_fail')
                element.text = 'cb: %s  replay: %s, launcher failed before pov started' % (self.hacked_cb_name, pov)
                drone = ET.SubElement(doc, 'drone')
                drone.text = self.szk.getTargetName()
                if self.rules is not None:
                    self.lgr.debug('launcherExitsNoReplay, rules set to %s' % self.rules)
                    rules_element = ET.SubElement(doc, 'rules')
                    rules_element.text = self.rules
                event_type = forensicEvents.LAUNCH_ERROR
                self.addLogEvent(cell_name, pid, comm, event_type, 'launcher post fork pre-exec failure TLV?')
                log = ET.tostring(doc)
                self.rpm.replayDone(self.hacked_cb_name, pov, log, self.rules)
            except kazoo.exceptions.NoNodeError:
                self.lgr.error('launcherExitsNoReplay failed to create replay done node')
        self.rules=None

    def setHackedCB(self, name):
        self.hacked_cb_name = name

    def setRules(self, rules):
        ''' typically rules are passed in with the newCB call, but in launch fail cases, need hack to fallback on '''
        ''' TBD tied to seed or alternate way to cover launch fails. '''
        self.rules = rules

    def replayExits(self, pid, cell_name):
        '''
        Handle case where replay exits while cb name defined, e.g., if CB fails validation
        ''' 
        self.lgr.debug('targetLog replayExits %d %s' % (pid, cell_name))
        seed = self.findSeed(pid, cell_name)
 
        if seed is not None and seed in self.cb_name[seed]:
            self.lgr.debug('call to replayExits in targetLog while cb %s defined, cb or PoV failed validation?' % self.cb_name[seed])
            cb = self.cb_name[seed]
            replay = self.replay_name[seed]
            log = self.getEntry(seed, True)
            self.lgr.debug('targetLog replayExits cb %s replay %s to: %s' % (cb, replay, log))
            try:
                self.rpm.replayDone(cb, replay, log, self.rules)
            except kazoo.exceptions.NoNodeError:
                self.lgr.error('could not create replay done node');
            self.resetState(seed)

    def checkAlreadyDone(self, cell_name, pid):
        if cell_name not in self.done_pids:
            self.done_pids[cell_name] = []
        if pid in self.done_pids[cell_name]:
            ''' already reported as done, return '''
            return True
        else:
           self.done_pids[cell_name].append(pid)
           if len(self.done_pids[cell_name]) > 5:
               self.done_pids[cell_name].pop(0) 

    ''' complete the log and add it to the replay node in the zookeeper hierarchy 
        If the replay is complete, signal that replay is done by creating
        its DONE node in the zk hierarchy, but only if not debugging binary.
    '''
    def doneItem(self, debugBinary, debug_event, is_player, cell_name, pid, comm, force=False):
        if self.checkAlreadyDone(cell_name, pid):
            self.lgr.debug('targetLog, doneItem, already called for %s %d' % (cell_name, pid))
            return
        seed = self.findSeed(pid, cell_name)
        if seed not in self.done_items:
            self.lgr.debug('targetLog doneItem, seed not found, already cleared? %s' % seed)
            return False
        self.lgr.debug('targetLog doneItem, %s %d (%s) debugBinary is %r debug_event is %r seed: <%s>, done_items %d need %d' % (cell_name, pid, comm, debugBinary, 
              debug_event, seed, self.done_items[seed], self.needed_items[seed]))
        if force:
            self.lgr.debug('doneItem, force is true, cause process to close out, may lose syscalls etc.')
        retval = False
        if seed not in self.doc:
            self.lgr.debug('call to doneItem in targetLog with no document created for seed %s, perhaps a CB that would not load?' % seed)
            self.resetState(seed)
            return True
        if comm != 'cfe-poller':
            self.done_items[seed] = self.done_items[seed] + 1
        self.debug_event[seed] = self.debug_event[seed] | debug_event
        if (self.done_items[seed] >= self.needed_items[seed]) or (is_player and self.num_cbs[seed] < self.expected_cbs[seed]) or force:
            retval = True
            if seed not in self.ts:
                self.lgr.info('targetLog doneItem before replay starts! (ts is not set anyway for seed %s' % seed)
                self.ts[seed] = time.time()
            done_ts = time.time()
            dt = datetime.datetime.fromtimestamp(done_ts)
            st = dt.strftime('%Y-%m-%d %H:%M:%S')
            end = ET.SubElement(self.doc[seed], 'time_end')
            end.text = st
            start_dt = datetime.datetime.fromtimestamp(self.ts[seed])
            took = done_ts - self.ts[seed]
            duration = ET.SubElement(self.doc[seed], 'duration')
            duration.text = format(took, '.2f')
            #duration.text = '%.2f' % took
            drone = ET.SubElement(self.doc[seed], 'drone')
            drone.text = self.szk.getTargetName()
            if seed in self.cb_name and seed not in self.replay_name:
                # poll/pov may have died before CB starts, or pov not started yet
                if seed in self.previous_replay_name:
                    self.replay_name[seed] = self.previous_replay_name[seed]
                    self.lgr.debug('targetLog done item, seed %s missing from replay_name, use previous of %s' % (seed, self.previous_replay_name[seed]))
                else:
                    self.lgr.debug('targetLog done item, seed %s missing from replay_name, also missing from previous_replay_name!' % (seed))
                self.previous_cb_name[seed] = self.cb_name[seed]

            if seed in self.cb_name and seed in self.replay_name:
                if is_player and self.num_cbs[seed] < self.expected_cbs[seed]:
                    load_fail = ET.SubElement(self.doc[seed], 'load_fail')
                    load_fail.text = 'cb bins loaded: %d  expected %d' % (self.num_cbs[seed], self.expected_cbs[seed])
                    self.lgr.debug('targetLog Player must have died before CBs created, or CB load failed.  Got %d CBs, expected %d' % (self.num_cbs[seed], self.expected_cbs[seed])) 
                cb = self.cb_name[seed]
                replay = self.replay_name[seed]
                if seed in self.protected_access and len(self.protected_access[seed]) > 0:
                    pa_pid, pa_server = self.findPidServerFromSeed(seed)
                    for pa in self.protected_access[seed]: 
                        json_dump = json.dumps(pa, default=utils.jdefault)
                        self.addLogEvent(pa_server, pa_pid, "CB", forensicEvents.USER_MEM_LEAK, 
                            json_dump , low_priority=True)
                        if pa.cpl == 0 and pa.length >=4 and self.master_cfg.track_protected_access:
                            self.lgr.critical('4 byte write by kernel from magic page %s' % json_dump)
                log = self.getEntry(seed, True)
                self.lgr.debug('targetLog Logging cb %s replay %s size of log is %d' % (cb, replay, len(log)))
                self.lgr.debug(log)
                if not debugBinary:
                    try:
                        self.rpm.replayDone(cb, replay, log, self.rules)
                    except kazoo.exceptions.NoNodeError:
                        self.lgr.error('could not create replay done node');
                self.ts.pop(seed, None) 
                if debugBinary and not self.debug_event[seed]:
                    # add throw to let any waiting ida clients know nothing landed.  dumb up the cb suffix
                    self.throw_mgr.addThrow(cb+'_01', replay, self.szk.getTargetName(), 'no faults', 'NO_EVENT')
                    self.rpm.doneDebug(replay)
            elif seed in self.replay_name:
                replay = self.replay_name[seed]
                self.lgr.debug('targetLog, player/pov <%s> exits before cb starts? rules is %s' % (replay, self.rules))
                self.previous_replay_name[seed] = replay
                if self.cfg.cfe:
                    event_type = forensicEvents.LAUNCH_ERROR
                    self.addLogEvent(cell_name, pid, comm, event_type, 'player exits before cb starts, TLV error?')
                    ''' call it done '''
                    log = self.getEntry(seed, True)
                    package = self.szk.getLatestLocalPackage(self.lgr)
                    if package is None:
                        self.lgr.debug('launcherExitsNoReplay, no package')
                        return
                    cb_name = package.find('cb_name').text
                    if self.rules is None:
                        rules_entry = package.find('rules')
                        if rules_entry is not None: 
                            self.rules = rules_entry.text
                         
                    try:
                        self.rpm.replayDone(cb_name, replay, log, self.rules)
                        self.lgr.debug('targetLog Logging cb which did not launch?  %s replay %s size of log is %d' % (cb_name, replay, len(log)))
                    except kazoo.exceptions.NoNodeError:
                        self.lgr.error('could not create replay done node for cb name from getLatestLocalPackage%s %s' % (cb_name, replay))
                    self.lgr.debug(log)
                    
                    self.ts.pop(seed, None) 
                    retval = True
                else:
                    retval = False
            else:
                self.lgr.error('targetLog doneItem called but no names set')
                retval = False
            self.resetState(seed)
            self.lgr.debug('targetLog doneItem returning %r' % retval)
        return retval

    def addLogEvent(self, cell_name, pid, comm, event_type, log, low_priority=False):
        seed = self.findSeed(pid, cell_name)
        retval = None
        kind = 'CB'
        if self.top.isReplay(comm):
            kind = 'replay'
        elif self.top.isPlayer(comm):
            kind = 'player'
        elif self.top.isIDS(comm):
            kind = 'ids'
        self.lgr.debug('addLogEvent for %s:%d (%s) kind is %s type: %d log: %s' % (cell_name, 
            pid, comm, kind, event_type, log))
        if seed in self.doc:
            add_it = True
            if low_priority:
                # keep things like bad syscalls from overwelming the log
                count = len(self.doc[seed].findall('event'))
                if count > 5:
                   add_it =  False
            if add_it:
                entry = ET.SubElement(self.doc[seed],'event')
                source = ET.SubElement(entry, 'source') 
                kind_e = ET.SubElement(source, 'kind') 
                kind_e.text = kind
                pid_e = ET.SubElement(source, 'pid') 
                pid_e.text = '%d' % pid
                comm_e = ET.SubElement(source, 'comm') 
                comm_e.text = comm
                descrip = ET.SubElement(entry, 'descrip') 
                descrip.text = log
                event_type_e = ET.SubElement(entry, 'event_type') 
                event_type_e.text = '%d' % event_type
        else:
            self.lgr.error('addLogEvent but no log for %s:%d (%s) kind is %s type: %d log: %s' % (cell_name, 
                pid, comm, kind, event_type, log))
            
    def addProtectedAccess(self, access, pid, cell_name):
        '''
        Track access to magic page, and consolidate small reads into bigger reads
        '''
        seed = self.findSeed(pid, cell_name)
        if len(self.protected_access[seed]) > 0:
            last_item = len(self.protected_access[seed]) - 1
            prev = self.protected_access[seed][last_item]
            if (access.location == (prev.location + access.length)) and \
                      access.delta <= (prev.delta + 80):
                prev.location = access.location
                prev.delta = access.delta
                prev.length = prev.length + access.length
            else:
                self.protected_access[seed].append(access)
        else:
            self.protected_access[seed].append(access)
                 
        

    def doneDebug(self, replay):
        self.lgr.debug('addLogEvent doneDebug %s' % replay)
        self.rpm.doneDebug(replay)

    
