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
#
#  Run a replay and start Ida if it goes to the debugger
#
import xml.etree.ElementTree as ET
import socket
import subprocess
import time
import os
import sys
import logging
import shutil
import glob
import signal
import json
import argparse
from subprocess import Popen
try:
    from monitorLibs import szk
    print("found monitorLibs")
except:
    print("appending ../zk to sys.path")
    sys.path.append('../zk')
    from monitorLibs import szk
from monitorLibs import throwMgr
from monitorLibs import configMgr
from monitorLibs import packageMgr
from monitorLibs import accessSQL
from monitorLibs import utils
from monitorLibs import dbgQueue
from monitorLibs import updateMasterCfg
from monitorLibs import povJson
from monitorLibs import getMonitor
from monitorLibs import cfeCsetConfig
from monitorLibs import gameThrowJson

round_dir = '/mftdata/cgc-archive/final/cgc/run/luigi/status/round'
def defaultJsons(cb, replay, pov_count, team_count):
    #print('get default json for %s %s pov_count: %d team_count: %d' % (cb, replay, pov_count, team_count))
    pov_json = povJson.getPovJson(cb, "/tmp/tmpReplays/"+replay, team_count=team_count)
    neg_json = povJson.getNegJson(cb, team_count=team_count)
    #print('pov_json: %s' % pov_json)
    #print('neg_json: %s' % neg_json)
    return pov_json, neg_json

def getDoneAlready():
    remote = 'bladet1'
    shell_out = subprocess.Popen(['/usr/bin/ssh','-o StrictHostKeyChecking=no', remote, 'ls', '/mnt/vmLib/bigstuff/auto_analysis/*.json'],
             stdout=subprocess.PIPE)
    output,err = shell_out.communicate()
    files = output.strip().split()
    return files

class oneThrow():
    def __init__(self, repo_host, auto_analysis):
        self.lgr = utils.getLogger('oneThrow', './logs')
        hostname = socket.gethostname()
        self.cfg = configMgr.configMgr()
        self.zk = szk.szk(hostname, self.cfg)
        self.throw_mgr = throwMgr.throwMgr(self.zk, self.lgr)
        self.gm = getMonitor.getMonitor(self.zk, self.cfg, self.lgr)
        self.dbg_queue = dbgQueue.dbgQueue(self.zk, self.lgr)
        self.auto_analysis = auto_analysis
        umc = updateMasterCfg.updateMasterCfg(self.zk, self.cfg, self.lgr)
        #self.checksum = self.storeConfig()
        self.checksum = umc.getChecksum(szk.MASTER_DEBUG_CONFIG_NODE)
        self.done = False
        self.local_stage = './stage'
        #self.repoHost = 'blade17'
        #self.repoHost = self.cfg.repo_master
        self.repoHost =  repo_host
        self.cb = None
        self.replay = None
        self.my_client_id = hostname
        self.my_client_node = self.zk.getClientDbgNode(self.my_client_id)
        self.queue_entry=None
        self.cfe_cfg = None

    def setAutoAnalysis(self, value):
        self.auto_analysis = value

    def storeConfig(self):
        sql = accessSQL.accessSQL(self.cfg.db_name, self.lgr)
        value = None
        local = './master.cfg'
        if os.path.exists(local):
            try:
                value = open('./master.cfg', 'rb').read()
                #print('Using LOCAL copy of master.cfg')
                checksum = utils.getChecksum(value)
                sql.addConfig(value, checksum)
            except:
                print('error reading local config %s' % local)
                exit(1)
        else:
            checksum = self.cfg.master_dbg_config
            config = sql.getConfig(checksum)
            if config is None:
                print('configMgr says debug config checksum is %s, but that is not in the database' % checksum)
                self.lgr.error('configMgr says debug config checksum is %s, but that is not in the database' % checksum)
                exit(1)
            print('Using master_dbg.cfg from the vmLib')
            self.lgr.debug('Using master_dbg.cfg from the vmLib')
        return checksum


    def runIda(self, throw, node):
        t = self.throw_mgr.decodeThrow(throw)
        if t.kind == 'NO_EVENT':
            print('throw of %s against %s caused no event' % (self.replay, self.cb))
            self.lgr.debug('throw of %s against %s caused no event' % (self.replay, self.cb))
            self.throw_mgr.throwDone(node)
            self.done = True
            return
        path = None
        ida_full = '/usr/share/cgc-monitor/rev.py'
        if not os.path.isfile(ida_full):
            rel_path = '../simics/ida/rev.py'
            ida_full = os.path.abspath(rel_path)
        #print('ida_full is %s' % ida_full)
        self.lgr.debug('ida_full is %s' % ida_full)
        print('kind is %s, t.cb: %s  t.replay: %s' % (t.kind, t.cb, t.replay))
        self.lgr.debug('kind is %s, cb: %s  replay: %s' % (t.kind, t.cb, t.replay))
        suffix = '01'
        if t.cb.endswith('.rcb'):
            cb = t.cb
        else:
            cb, suffix = self.zk.cbFromComm(t.cb)
            if suffix is None:
                print 'CB %s missing suffix' % t.cb
                exit(1)
        fname = cb
        if self.cfe_cfg is None or (cb.startswith('CB') and t.kind == 'CB'):
            path = self.zk.pathFromName(self.cfg.cb_dir, cb)
            path = path + "_" + suffix
            print('using reference path of %s' % path)
        else:
            if t.kind == 'CB':
                path = self.getRcbPath(t.cb)
            else:
                path = self.getPovPath(t.cb, t.replay)
                fname = t.replay+'.pov'
                print('fname is %s' % fname)
        if not os.path.isfile(path):
            print 'first pathFromName not found: %s, expected look at local' % path
            path = os.path.join(self.getLocalPath(path), fname)
            if self.cfe_cfg is None or (cb.startswith('CB') and t.kind == 'CB'):
                path = path + "_" + suffix
            if not os.path.isfile(path):
                print('runIda could not find local file: %s' % path)
                self.lgr.debug('runIda could not find local file: %s' % path)
                exit(1)
        parts = t.target_name.split('_')
        ip = parts[0]
        instance = parts[1]
        port = 9123 + int(instance)
        #print 'path for analysis: %s port: %d' % (path, port)
        self.lgr.debug('path for analysis: %s port: %d' % (path, port))
        cmd='startIda.sh %s %s %s %s %s' % (path, ida_full, ip, instance, port)
        os.system(cmd)
        #sp
        #subprocess.call(['./startIda.sh', path, ida_full, ip, instance, port])
        #print 'back from startIda'
        self.throw_mgr.throwDone(node)
        self.done = True
   
    def myWatcher(self, event):
        #print 'in myWatcher, path is %s' % event.path
        self.lgr.debug('in myWatcher, path is %s' % event.path)
        throw = None
        if not self.auto_analysis:
            throw, node = self.throw_mgr.getThisThrow(self.myWatcher, self.cb, self.replay, self.my_client_id)
        if throw is not None and not self.done:
            print('runIda for throw %s, node %s' % (throw, node))
            self.runIda(throw, node)
            self.done = True

    def doPackageOwnPP(self, cb, replay):
        self.lgr.debug('doPackageOwnPP for %s %s' % (cb, replay))
        self.cb = cb
        self.replay = replay
        throw = None
        if not self.auto_analysis:
            throw, node = self.throw_mgr.getThisThrow(self.myWatcher, cb, replay, self.my_client_id)
        if throw is None:
            self.lgr.debug('doPackageOwnPP, instantiate packageMgr')
            pp = packageMgr.packageMgr(self.zk, self.lgr, self.cfg, '0', False, self.checksum)
            replays = {replay}
            test_package = utils.getEncodedPackage(cb, replays, self.checksum)
            self.lgr.debug('doPackageOwnPP, call localCopyPackage')
            pp.xmlParse(test_package)
            pp.localCopyPackage(test_package)
            pp.doOnePackage(test_package)
            self.localCopyPackage(test_package, True)
            #pp.waitUntilConsumerDone()
            #pp.lgr.debug('consumer done with package') 
        else:
            print('doPackageOwnPP found throw before enqueuing!')
            self.lgr.debug('doPackageOwnPP found throw before enqueuing!')
            self.runIda(throw, node)
       
 
    def doPackage(self, cb, replay):
        if replay.startswith('POV') and not replay.lower().endswith('.pov'):
            replay = replay+'.pov'
        self.cb = cb
        self.replay = replay
        #print('in doPackage for %s %s' % (cb, replay))
        self.lgr.debug('in doPackage for cb: %s replay: %s' % (cb, replay))
        replays = []
        replays.append(replay)
        throw = None
        if not self.auto_analysis:
            throw, node = self.throw_mgr.getThisThrow(self.myWatcher, cb, replay, self.my_client_id)
        if throw is None:
            pov_json, neg_json = defaultJsons(cb, replay, 1, 1)
            package = utils.getEncodedPackage(cb, replays, self.checksum, no_timeout=True, client_id=self.my_client_id, client_node=self.my_client_node, pov_json=pov_json, neg_json=neg_json)
            self.queue_entry = self.dbg_queue.addReplay(package)
            self.localCopyPackage(package)
            print('doPackage added replay to dbgQueue %s %s' % (cb, replay))
            self.lgr.debug('doPackage added replay to dbgQueue %s %s.  clientnode: %s' % (cb, replay, self.my_client_node))
        else: 
            print('doPackage found throw before enqueuing!')
            self.lgr.debug('doPackage found throw before enqueuing!')
            self.runIda(throw, node)

    def rmQueue(self):
        self.zk.zk.delete(self.queue_entry, recursive=True)

    def getLocalPath(self, path):
        index = path.find('CBs')
        local = os.path.join(self.local_stage, path[index:])
        return os.path.dirname(local)

    def checkBins(self, path):
        retval = True
        cb = os.path.basename(path) 
        csid = utils.getCSID(cb)
        num_bins = utils.numBins(csid)
        #print('checkBins num bins in %s is %d' % (cb, num_bins))
        for i in range(1, num_bins+1):
            f = os.path.join(path, cb+'_%02x' % i)
            if not os.path.isfile(f):
                #print('checkBins, not a file: %s' % f)
                return False
        return retval

    def doLocalscp(self, path, local=False):
        '''
        '''
        retval = True
        print 'doLocalscp path is %s' % path
        local = self.getLocalPath(path)
        print 'local is %s ' % local
        if not self.checkBins(local):
            try:
                os.makedirs(local)
            except:
                pass
            # include wildcard to get multi-binary CBs and ida db files
            the_files = glob.glob(path+'*')
            if len(the_files) == 0:
                source = 'cgc@%s:%s*' % (self.repoHost, path)
                #print('source is %s local: %s' % (source, local))
                retcode = subprocess.call(['/usr/bin/scp','-P 2444', '-o StrictHostKeyChecking=no', source, local])
                if retcode != 0:
                    print('scp Error, retcode is %d' % retcode)
                    retval = False
            else:
                for f in the_files:
                    #print 'copy from '+f+' to '+local
                    shutil.copy(f, local)

        return retval

    def localCopyPackage(self, package, local = False):
        root = ET.fromstring(package)
        cb_name = root.find('cb_name').text
        path = self.zk.pathFromName(self.cfg.cb_dir, cb_name)
        if not self.doLocalscp(path, local):
            print 'bad path: %s for CB %s not found, exiting' % (path, cb_name) 
            self.lgr.debug('bad path: %s for CB %s not found, exiting' % (path, cb_name))
            exit(1)

    def stop(self):
        self.zk.stop()
        '''
        for pov in root.iter('pov'):
           pov_path = self.zk.replayPathFromName(pov.text)+'.xml'
           self.doLocalscp(pov_path) 
        for poll in root.iter('poll'):
           poll_path = self.zk.replayPathFromName(poll.text)+'.xml'
           self.doLocalscp(poll_path) 
        '''
    def fromConfig(self, fname, seed_index, debug_cb, debug_pov):
        ''' get the package from a forensics json file provided by infrastructure '''
        remote = 'cgc@%s' % (self.repoHost)
        #print('remote is %s seed_index is %d' % (remote, seed_index))
        shell_out = subprocess.Popen(['/usr/bin/ssh','-p 2444', '-o StrictHostKeyChecking=no', remote, 'listCFE', '-j', fname], 
             stdout=subprocess.PIPE)
        output,err = shell_out.communicate()
        #print('config is: <**%s**>' % output)
        self.cfe_cfg = cfeCsetConfig.cfeCsetConfig()
        try:
            self.cfe_cfg.loadFromString(output) 
        except:
            print('bad response: <%s> from listCFE -j %s' % (output, fname))
        rcb_paths = self.cfe_cfg.getRCBs()
        rcbs = []
        for rcb in rcb_paths:
            rcbs.append(os.path.basename(rcb))
        pov = self.cfe_cfg.getPov()
        pov = os.path.basename(pov)
        self.replay = pov
        rules = self.cfe_cfg.getIDS()
        rules = os.path.basename(rules)
        team = self.cfe_cfg.getTeamId()
        common = self.cfe_cfg.getCommonName()
        pov_config = self.cfe_cfg.getPovConfig()
        if pov_config is not None:
            # convert to string so can convert back to json.  doh!
            pov_config = json.dumps(pov_config)
        #print('package:\n%s' % test_package)
        cb_id = rcbs[0]
        self.cb= cb_id
        throw = None
        if not self.auto_analysis:
            throw, node = self.throw_mgr.getThisThrow(self.myWatcher, cb_id, pov, self.my_client_id)
        if throw is None:
            package = self.gm.buildPackageXML(cb_id, pov, 'debug', self.checksum, rcbs, rules, str(team), 
                pov_config=pov_config, no_timeout=True, client_id=self.my_client_id, 
                client_node=self.my_client_node, seed_index=seed_index, debug_cb=debug_cb, debug_pov=debug_pov)
            self.queue_entry = self.dbg_queue.addReplay(package)
            self.localCopyNoContext(common, rcbs, team, pov, debug_pov)
            print('fromConfig added replay to dbgQueue %s %s' % (rcbs[0], pov))
            self.lgr.debug('fromConfig added replay to dbgQueue %s %s.  clientnode: %s' % (rcbs[0], pov, self.my_client_node))
        else: 
            print('fromConfig found throw before enqueuing!')
            self.lgr.debug('fromConfig found throw before enqueuing!')
            self.runIda(throw, node)

    def getCommonName(self, rcb):
        cb_name = rcb.split('-')[1]
        if cb_name.count('_') == 2:
            ''' multi binary, assume last is count? '''
            parts = cb_name.split('_')
            suffix = parts[2]
            num_bins = '%02d' % int(suffix)
            common = 'CB'+parts[0]+'_'+parts[1]+num_bins 
        else:
            common = 'CB'+cb_name+'01'
        return common 

    def fromGame(self, my_json, team, seed_index, debug_cb, debug_pov, patched=False, throw_id=None):
        remote = 'cgc@%s' % (self.repoHost)
        ''' load just for use by prep for ida '''
        self.cfe_cfg = cfeCsetConfig.cfeCsetConfig()
        try:
            self.cfe_cfg.loadFromString(json.dumps(my_json)) 
        except:
            print('could not load cfe_cfg json')
            exit(1)
        #print self.cfe_cfg.toString()
        full_rcbs = my_json['rcb']
        rcbs = []
        for path in full_rcbs:
            rcbs.append(os.path.basename(path))
        rules = my_json['ids']
        pov_config = json.dumps(my_json['pov_config'])
        #print str(pov_config)
        replay = my_json['pov']
        pov = os.path.basename(replay)
        self.replay = pov
        cb_id = rcbs[0]
        common = self.getCommonName(cb_id)
        if patched:
            cb_id = common+'_MG'
            rcbs = None
        #if pov_config is not None:
        #    # convert to string so can convert back to json.  doh!
        #    pov_config = json.dumps(pov_config)
        #print('package:\n%s' % test_package)
        self.cb= cb_id
        throw = None
        if not self.auto_analysis:
            throw, node = self.throw_mgr.getThisThrow(self.myWatcher, cb_id, pov, self.my_client_id)
        if throw is None:
            package = self.gm.buildPackageXML(cb_id, pov, 'debug', self.checksum, rcbs, rules, str(team), 
                pov_config=pov_config, no_timeout=True, client_id=self.my_client_id, 
                client_node=self.my_client_node, seed_index=seed_index, debug_cb=debug_cb, debug_pov=debug_pov, throw_id=throw_id,
                auto_analysis=self.auto_analysis)
            self.queue_entry = self.dbg_queue.addReplay(package)
            if not patched:
                self.localCopyNoContext(common, rcbs, team, pov, debug_pov)
                print('fromGame added replay to dbgQueue %s %s' % (rcbs[0], pov))
                self.lgr.debug('fromGame added replay to dbgQueue %s %s.  clientnode: %s' % (rcbs[0], pov, self.my_client_node))
            else:
                self.localCopyPackage(package)
        elif not self.auto_analysis: 
            print('fromGame found throw before enqueuing!')
            self.lgr.debug('fromGame found throw before enqueuing!')
            self.runIda(throw, node)

    def getPovPath(self, rcb, pov):
        team_id = self.cfe_cfg.getTeamId()
        common = self.cfe_cfg.getCommonName()
        team_num = int(team_id)
        team_pad = '%03d' % team_num
        rcb_id, dum = os.path.splitext(rcb)
        path = os.path.join(self.cfg.cb_dir, common, szk.COMPETITOR, team_pad, 'povs',rcb_id)
        print('getPovPath got %s' % path)
        return path

    def getRcbPath(self, rcb):
        ''' TBD fix for multibinary '''
        common = self.cfe_cfg.getCommonName()
        team_id = self.cfe_cfg.getTeamId()
        team_num = int(team_id)
        team_pad = '%03d' % team_num
        rcb_id, dum = os.path.splitext(rcb)
        path = os.path.join(self.cfg.cb_dir, common, szk.COMPETITOR, team_pad, 'cbs',rcb_id, rcb)
        return path
         
    def localCopyNoContext(self, common, rcbs, team_id, pov, debug_pov):
        team_num = int(team_id)
        team_pad = '%03d' % team_num
        rcb_id = os.path.basename(rcbs[0])
        rcb_id, dum = os.path.splitext(rcb_id)
        #prefix = rcb_id.split('-')[0]
        #print('rcb_id is <%s> common is <%s> team: %s' % (rcb_id, common, team_pad))
        if not debug_pov:
            path = os.path.join(self.cfg.cb_dir, common, szk.COMPETITOR, team_pad, 'cbs',rcb_id, rcb_id)
        else:
            path = os.path.join(self.cfg.cb_dir, common, szk.COMPETITOR, team_pad, 'povs', pov)
        print('call doLocalscp for path %s' % path)
        if not self.doLocalscp(path):
            if not debug_pov:
                print 'bad path: %s for CB %s not found, exiting' % (path, rcb_id) 
                self.lgr.debug('bad path: %s for CB %s not found, exiting' % (path, rcb_id))
            else:
                print 'bad path: %s for POV %s %s not found, exiting' % (path, rcb_id,pov) 
                self.lgr.debug('bad path: %s for POV %s %s not found, exiting' % (path, rcb_id, pov))

    def parseScores(self, fname):
        rcb_string = '/var/cgc/run/cb'
        new_string = '/mnt/vmLib/bigstuff/cfe-games/cgc-forensics/1470326433.800818'
        count=0
        already_done = getDoneAlready()
        with open(fname) as fh:
            for line in fh:
                #  CROMU_00046,6,1,1,58,9
                print line.strip()
                parts = line.split(',')
                csid = parts[0]
                print('csid is %s' % csid)
                thrower = int(parts[1])
                defend = int(parts[2])
                pov_type = parts[3]
                round_id = parts[4]
                throw_num = int(parts[5])-1
                ''' hack to not skip what has been done, and only do one throw per '''
                throw_id = '%s-%s-%s-%s' % (csid, thrower, defend, round_id)
                #throw_id = '%s-%s-%s' % (csid, thrower, defend)
                #throw_fname = throw_id+'-analysis.json'
                didit = False
                for already in already_done:
                    base = os.path.basename(already)
                    if base.startswith(throw_id):
                        didit = True
                        break
                if didit:
                    continue
                count += 1
                already_done.append(throw_id)
                throw_id = '%s-%s-%s-%s-%s' % (csid, thrower, defend, round_id, throw_num+1)
                session_json = gameThrowJson.getJson(csid, round_id, thrower, defend)
                #print(str(session_json))
                the_string = json.dumps(session_json)
                output = the_string.replace(rcb_string, new_string)
                session_json = json.loads(output)
                self.fromGame(session_json, defend, throw_num, False, False, throw_id=throw_id)
                print('back from fromGame')
                #if count > 2:
                #    exit(0)
                print('******************************DONE with throw_id %s %d' % (throw_id, count))
        print('count is %d' % count)

def signal_handler(signal, frame):
    print('oneThrow signal caught, exit')
    exit(1)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    retval = subprocess.call(['checkMonitorEnv.sh'])
    if retval != 0:
        print('problem with environment')
        exit(1)
    repo_host = 'localmonitor'
    parser = argparse.ArgumentParser(description="Replay a session on the CGC Monitor under control of gdb & an Ida client")
    parser.add_argument("cb_or_json", help="The name of a json file from cgcflow, or a rcb name", type=str)
    parser.add_argument("replay_or_round", nargs='?', default=None, help="Optional name of pov or poll, provide if first argument is a cb", type=str)
    parser.add_argument("thrower", nargs='?', default=None, help="thrower", type=int)
    parser.add_argument("defend", nargs='?', default=None, help="defender", type=int)
    parser.add_argument("alt_defend", nargs='?', default=None, help="alt_defender", type=int)
    parser.add_argument("alt_round", nargs='?', default=None, help="alt_defender", type=int)
    parser.add_argument("-s", "--seed", default=0, help="seed index, defaults to first seed (zero)", type=int)
    parser.add_argument("-f", "--file_name", default=None, help="file name to parse for replays", type=str)
    parser.add_argument("-d", "--debug_cb", action='store_true', default=False, help="stop debugger as soon as cb loads")
    parser.add_argument("-dp", "--debug_pov", action='store_true', default=False, help="stop debugger as soon as pov loads")
    parser.add_argument("-p", "--pov",  nargs='?', default=None, const=1, action='store',
          help="if just a CSID is provided, run the author PoV against it.", type=int)
    parser.add_argument("-a", "--auto_analysis", action='store_true', default=False, help="auto analysis, don't wait for finish")
    parser.add_argument("-m", "--patched", action='store_true', default=False, help="Use reference patched in place of RCB")
    args = parser.parse_args()
    ot = oneThrow(repo_host, args.auto_analysis)
    if args.file_name is not None:
        print('got fname %s' % args.file_name)
        ot.setAutoAnalysis(True) 
        ot.parseScores(args.file_name)
    elif args.cb_or_json.endswith('.json'):
        debug_cb = False
        ot.fromConfig(args.cb_or_json, args.seed, args.debug_cb, args.debug_pov)
        print('back from enqueuing, wait until done... may take a moment')
        while not ot.done:
            time.sleep(2)
        ot.rmQueue()
        print('must be done')
        
    elif args.replay_or_round is not None:
        round_id = None
        try:
            round_id = int(args.replay_or_round)
        except:
            pass
        if round_id is None:
            ot.doPackage(args.cb_or_json, args.replay_or_round)
            while not ot.done:
                time.sleep(2)
            ot.rmQueue()
        else:
            round_dir = '/mftdata/cgc-archive/final/cgc/run/luigi/status/round'
            session_json = gameThrowJson.getJson(args.cb_or_json, round_id, args.thrower, args.defend, args.alt_defend, args.alt_round)
            print(str(session_json))
            rcb_string = '/var/cgc/run/cb'
            new_string = '/mnt/vmLib/bigstuff/cfe-games/cgc-forensics/1470326433.800818'
            the_string = json.dumps(session_json)
            output = the_string.replace(rcb_string, new_string)
            session_json = json.loads(output)
            defend = args.defend
            if args.alt_defend is not None:
                defend = args.alt_defend
            throw_id = '%s-%s-%s-%s-%s' % (args.cb_or_json, args.thrower, args.defend, round_id, args.seed+1)
            ot.fromGame(session_json, defend, args.seed, args.debug_cb, args.debug_pov, args.patched, throw_id)
            if not args.auto_analysis:
                print('back from enqueuing, wait until done... may take a moment')
                while not ot.done:
                    time.sleep(2)
                ot.rmQueue()
                print('must be done')
            else:
                print("done enqueuing")
           
            #ot.doPackageOwnPP(cb, replay)
    elif args.pov:
            remote = 'cgc@%s' % (repo_host)
            shell_out = subprocess.Popen(['/usr/bin/ssh','-p 2444', '-o StrictHostKeyChecking=no', remote, 'listRepo', args.cb_or_json,
                '-p'], stdout=subprocess.PIPE)
            output,err = shell_out.communicate()
            csid = None
            for line in output.splitlines():
                if line.startswith('POV'):
                    pov, csid = line.strip().split()
                    seq = pov.split('_')[4]
                    if int(seq) == args.pov:
                        break
            if csid is not None:
                ot.doPackage(csid, pov)
                while not ot.done:
                    time.sleep(2)
                ot.rmQueue()
        
    ot.stop()
