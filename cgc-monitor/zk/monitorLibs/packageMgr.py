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
import os
import time
import sys
import getMonitor
import socket
import logging
from threading import Thread, Lock, Condition
import configMgr
import xml.etree.ElementTree as ET
import shutil
import glob
import utils
#import accessSQL
import updateMasterCfg
import replayMgr
#import subprocess
#from subprocess import Popen
'''
Get packages from the getMonitor.  This looks at the entire node
hierarchy looking for sessions that have not yet been run.  Alternately,
a descrete package can be named in the inputs.
After putting a package, wait until the consumer indicates it is done before getting 
and putting the next package.
Gets configuration data from replay_master.xml
'''

class packageMgr():
    local_stage = None
    repoHost = None
    package_done_path = None
    def __init__(self, szk, lgr, cfg, instance, be_nice, checksum=None, dbg_queue=False, check_monitor=True, any_config=False, only_client=None):
        self.szk = szk
        self.be_nice = be_nice
        self.instance = instance
        self.cfg = cfg
        print("cfg.use_matic is %r" % self.cfg.use_matic)
        self.checksum = checksum
        self.rpm = replayMgr.replayMgr(szk, cfg)
        # parsed xml for performance
        self.root = None
        self.lgr = lgr
        if not self.szk.hasReplayCFG():
            self.lgr.error('missing replay configuration node')
            print('missing replay configuration node')
            self.hungSoDie()
        self.single_replays = cfg.single_replays
        self.gm = getMonitor.getMonitor(szk, self.cfg, self.lgr, dbg_queue, rpm=self.rpm, any_config=any_config, only_client=only_client)
        self.umc = updateMasterCfg.updateMasterCfg(szk, cfg, lgr)
        self.package_done_path = None
        self.counter_lock = Lock()
        self.counter = 0
        workspace, self.repoHost, self.local_stage = self.getReplayPath()
        try:
            os.makedirs(self.local_stage)
        except:
            pass
        pipe = os.path.join(workspace, 'simics.stdin')
        self.simics_stdin = open(pipe, 'a')
        if checksum is not None:
            # one-off instantiation of putPackages intended to run debugger
            # Use the master.cfg named by the checksum
            print('use alternate config: %s' % checksum)
            self.lgr.debug('packageMgr, init alternate config: %s' % checksum)
            self.alternateConfig(checksum)
        self.check_monitor = check_monitor
        if self.cfg.no_monitor:
            self.check_monitor = False
        if self.check_monitor:
            self.checkConfig()

    def readCounter(self):
        self.counter_lock.acquire()
        mycount = self.counter
        self.counter_lock.release()
        return mycount

    def incCounter(self):
        self.counter_lock.acquire()
        self.counter += 1
        self.counter_lock.release()

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
    
    def waitUntilMonitorReady(self):
        if not self.check_monitor:
            return
        done = False
        while not done:
            status_timestamp = self.szk.getOurStatus()
            if status_timestamp is None:
                self.lgr.debug('monitor not ready, no status node, wait a second')
                time.sleep(1)
            else: 
                monitor_config = None
                timestamp = None
                while monitor_config is None:
                    monitor_config, timestamp = self.szk.getOurChecksum(self.lgr)
                    if monitor_config is None:
                        self.lgr.debug('monitor not ready, wait a second')
                        time.sleep(1)
                    else:
                        self.lgr.debug('packageMgr waitUntilMonitorReady monitor must be ready')
                if timestamp == status_timestamp:
                    done = True
                else:
                    self.lgr.debug('waitUntilMonitorReady, timestamps do not match, try again')

    def alternateConfig(self, checksum):
        '''
        If the given checksum is not what the is in the master config node, define an alternate
        Returns true if an alternate was defined
        '''
        retval = False
        value, stat = self.szk.zk.get(szk.MASTER_CONFIG_NODE) 
        master_config = utils.getChecksum(value)
        self.lgr.debug('alternateConfig given checksum is %s, the checksum from the MASTER_CONFIG_NODE zk node is %s' % (checksum, master_config))
        if master_config != checksum:
            retval = True
            self.checksum = checksum

            monitor_config, timestamp = self.szk.getOurChecksum(self.lgr)
            if checksum != monitor_config:
                self.lgr.debug('alternateConfig, need to define alternate config node for given %s, master config was %s' % (checksum, master_config))
                #sql = accessSQL.accessSQL(self.cfg.db_name, self.lgr)
                #config = sql.getConfig(checksum)      
                config = self.umc.findMasterCfg(checksum)
                if config is None or len(config) < 10:
                    self.lgr.debug('packageMgr, alternateConfig, Could not get config for checksum %s, leftover dbgQueue entry?' % checksum)
                    return False
                config = self.editConfig(config)
                self.szk.putAlternateConfig(config)
                #sql.close()
            else:
                self.lgr.debug('alternateConfig, monitor started with what would have been the alternate, do not create alternate node')
        else:
            self.lgr.debug('alternateConfig, given checksum matches that in MASTER_CONFIG_NODE')
        return retval

    def editConfig(self, config):
        debug_cb = self.root.find('debug_cb')
        if debug_cb is not None:
            self.lgr.debug('editConfig, debug_cb, set, change setting in config')
            config = config.replace('debug_cb=no', 'debug_cb=yes')
            self.checksum = utils.getChecksum(config)
            if 'debug_cb=yes' not in config:
                self.lgr.error('debug_cb not set in %s' % config)
        else:
            debug_pov = self.root.find('debug_pov')
            if debug_pov is not None:
                self.lgr.debug('editConfig, debug_pov, set, change setting in config')
                config = config.replace('debug_cb=no', 'debug_cb=no\ndebug_pov=yes')
                self.checksum = utils.getChecksum(config)
                if 'debug_pov=yes' not in config:
                    self.lgr.error('debug_pov not set in %s' % config)
            else: 
                self.lgr.debug('debug_cb and debug_pov, NOT SET')
                pass
        return config

    def alternateMasterConfig(self, config):
        '''
        Copy the given configuration node into the alternate
        TBD alternates are always deleted between sessions, so will always return true.
        Fix to optimize and not restart monitor.
        '''
        self.lgr.debug('alternateMasterConfig for config %s' % config)
        retval = False
        node = None
        if config == 'debug':
            node = szk.MASTER_DEBUG_CONFIG_NODE
        elif config == 'analysis':
            node = szk.MASTER_ANALYSIS_CONFIG_NODE
        elif config == 'msc':
            node = szk.MASTER_MSC_CONFIG_NODE
        elif config == 'pov':
            node = szk.MASTER_POV_CONFIG_NODE
        else:
            self.lgr.error('alternateMasterConfig unknown config type: %s' % (config))
            return False
           
        value, stat = self.szk.zk.get(node)
        current = self.szk.getAlternateConfig()
        
        if current is None or current != value:
            self.lgr.debug('copying config: %s to alternate' % config)
            value = self.editConfig(value)
            self.szk.putAlternateConfig(value)
            retval = True
        return retval

    '''
        Make sure the current configuration matches what the monitor was started with.
        If a mismatch is found, restart the monitor.
    '''
    def checkConfig(self, event=None, config_name='master'):
        monitor_config, timestamp = self.szk.getOurChecksum(self.lgr)
        config_node, dum = self.szk.nodeFromConfigName(config_name)
        if self.checksum is None:
            value, stat = self.szk.zk.get(config_node) 
            checksum = utils.getChecksum(value)
            self.lgr.debug('checkConfig got config from master configuration "%s" node, checksum is %s' % (config_name, checksum))
            #print('checkConfig got config from zk node, checksum is %s' % checksum)
        else:
            checksum = self.checksum
            self.lgr.debug('checkConfig got config from dequeued package, checksum is %s' % checksum)
            print('checkConfig got config from dequeued package, checksum is %s' % checksum)

        if monitor_config != checksum:
            print('checkConfig configurations do not match current: %s monitor started with: %s, reInit cgcMonitor and try again' % \
                 (checksum, monitor_config))
            self.lgr.debug('checkConfig configurations do not match current: %s  monitor started with: %s, reInit cgcMonitor and try again' % \
                          (checksum, monitor_config))
            success = self.szk.deleteOurReset()
            if not success:
                self.lgr.debug('checkConfig found reset node already deleted %d' % success)
            done = False
            count = 0
            while not done:
                monitor_config = None
                while monitor_config == None:
                    self.lgr.debug('checkConfig wait one second and try again to get master config')
                    time.sleep(1)
                    monitor_config, timestamp = self.szk.getOurChecksum(self.lgr)
                if self.checksum is None:
                    value, stat = self.szk.zk.get(config_node) 
                    checksum = utils.getChecksum(value)
                else:
                    checksum = self.checksum
                done = True
                if monitor_config != checksum:
                    print('checkConfig failed after attempt to reInit cgcMonitor')
                    self.lgr.debug('checkConfig failed after attempt to reInit cgcMonitor')
                    done = False
                    if count > 3:
                        self.lgr.error('checkConfig failed after 3 attempts to reInit cgcMonitor we see %s cgcMonitor reports %s' % (checksum, monitor_config))
                        self.hungSoDie()
                    else:
                        self.lgr.debug('checkConfig, wait three and try again.  count now %d' % count)
                        time.sleep(3)
                        count += 1
        self.checksum = checksum
        ''' tell the getMonitor we only want replays having this checksum '''
        #self.lgr.debug('checkConfig update getMonitor with new checksum %s' % checksum)
        self.gm.setChecksum(checksum)

    def doLocalcp(self, path, ftype):
        '''
        Uses nfs 
        '''
        index = path.find('CBs')
        local = self.local_stage+path[index:]
        parent = os.path.dirname(local)
        retval = True
        #print 'path is %s' % path
        #print 'parent is %s ' % parent
        try:
            os.makedirs(parent)
        except:
            pass
        # include wildcard to get multi-binary CBs
        #source = '%s:%s*' % (self.repoHost, path)
        #print 'source is %s' % source
        #retcode = subprocess.call(['/usr/bin/scp','-o StrictHostKeyChecking=no', source, parent])
        source = '%s*' % (path)
        print 'look at shared source '+source
        the_files = glob.glob(source) 
        if len(the_files) == 0:
            print('no files at %s' % source)
            self.lgr.error('no files at %s' % source)
            self.hungSoDie()
        for f in the_files:
            dest_path = os.path.join(parent, os.path.basename(f))
            if not os.path.isfile(dest_path):
                print 'copy from '+f+' to '+parent
                shutil.copy(f, parent)
                if self.cfg.use_matic:
                    print('run maticUpload.py with %s %s' % (dest_path, ftype))
                    self.simics_stdin.write('run-python-file /usr/bin/maticUpload.py %s %s' % (dest_path, ftype))
            else:
                print('%s already in local storexxx, skip' % dest_path)
        #print 'source is %s' % source
        #retcode = subprocess.call(['/bin/cp', source, parent])
        #if retcode != 0:
        #   retval = False
        return retval

    def noTimeout(self):
        retval = False
        try:
            no_timeout = self.root.find('no_timeout')
        except:
            return False
        if no_timeout is not None and no_timeout.text == 'TRUE':
            retval = True
        return retval
           
    def checkNeedAlternateConfig(self):
        '''
        Does this package request an alternate master.cfg?
        '''
        config = None
        try: 
            config = self.root.find('config_name').text
        except:
            pass
        if config is not None and config != 'master':
            '''
            Use one of the configuration nodes
            '''
            self.lgr.debug('checkNeedAlternateConfig, use one of the config nodes %s' % config)
            self.alternateMasterConfig(config)
            self.checkConfig(config_name=config)
        else:
            checksum = None
            try:
                checksum = self.root.find('config_checksum').text
            except:
                return False
            self.lgr.debug('checkNeedAlternateConfig, look for checksum %s' % checksum)
            self.alternateConfig(checksum)
            self.checkConfig()
        
    def xmlParse(self, package):
        try:
            self.lgr.debug('xmlParse')
            self.root = ET.fromstring(package)
        except:
            print('could not parse: %s' % package)
            self.lgr.error('xmlParse could not parse: %s' % package)
            self.hungSoDie()

    def getCommonName(self):
        #common = self.root.find('common')
        #if common is not None:
        #    return common.text
        rcb_list = []
        try:
            rcb_list = self.root.findall('cb_bin')
        except:
            self.lgr.error('packageManager, getCommonName, no rcb in package')
            exit(1)
        if len(rcb_list) > 1:
            for r in rcb_list:
                print('*********************** rcb %s' % r)
        num_bins = '%02d' % len(rcb_list)
        base = rcb_list[0].text
        cb_name = base.split('-')[1]
        parts = cb_name.split('_')
        cb_name = parts[0]+'_'+parts[1]
        common = 'CB'+cb_name+num_bins
        return common

    def localCopyPackageNoContext(self, package):
        self.lgr.debug('localCopyPackageNoContext begin')
        try:
            cb_name = self.root.find('cb_name').text
        except:
            self.lgr.error('localCopyPackageNoContext could not find cb_name in %s' % package)
            self.hungSoDie()
        try:
            team_id = self.root.find('team_id').text
        except:
            self.lgr.error('localCopyPackageNoContext could not find team_id in %s' % package)
            self.hungSoDie()
        pov_team=None
        try:
            pov_team = self.root.find('pov_team').text
            pov_team_num = int(pov_team)
            pov_team_pad = '%03d' % pov_team_num
        except:
            pass 
        common = self.getCommonName()
        team_num = int(team_id)
        team_pad = '%03d' % team_num
        ''' path and local may be redefined if author POV '''
        path = os.path.join(self.cfg.cb_dir, common, szk.COMPETITOR, team_pad)
        ids_path = path
        if pov_team is None:
            pov_path = path
        else:
            pov_path = os.path.join(self.cfg.cb_dir, common, szk.COMPETITOR, pov_team_pad)
        local = os.path.join(self.local_stage, common)
        local_ids = local
        self.lgr.debug('localCopyPackageNoContext %s %s %s' % (common, team_pad, path))
        try:
            os.makedirs(local)
        except:
            pass
        self.lgr.debug('localCopyPackageNoContext two')
        rcb_list = self.root.findall('cb_bin')
        rcb_id = os.path.basename(rcb_list[0].text)
        rcb_id, dum = os.path.splitext(rcb_id)
        rcb_id = utils.rmBinNumFromName(rcb_id)
        self.lgr.debug('localCopyPackageNoContext three')
        for rcb in rcb_list:
            src_path = os.path.join(path, 'cbs', rcb_id, rcb.text)
            dest_path = os.path.join(local, rcb.text)
            if not os.path.isfile(dest_path):
                print 'rcb copy from '+src_path+' to '+dest_path
                self.lgr.debug('rcb copy from '+src_path+' to '+dest_path)
                if not os.path.isfile(src_path):
                    print('***********missing file******, fatal: %s' % src_path)
                    self.lgr.error('localCopyPacakgeNoContext***********missing file******, fatal: %s' % src_path)
                    exit(1)
                shutil.copy(src_path, dest_path)
            else:
                print('already exists: %s' % dest_path)

        self.lgr.debug('localCopyPackageNoContext four')
        for poll in self.root.iter('poll'):
            src_path = self.szk.replayPathFromName(self.cfg.cb_dir, poll.text)+".xml"
            dest_path = os.path.join(local, poll.text)
            if not os.path.isfile(dest_path):
                print 'poll copy from '+src_path+' to '+dest_path
                shutil.copy(src_path, dest_path)
            else:
                print('already exists: %s' % dest_path)
        self.lgr.debug('localCopyPackageNoContext five')
        pov = self.root.find('pov')
        if pov is not None and pov.text is not None:
            if pov.text.startswith('POV'):
                path = os.path.join(self.cfg.cb_dir, common, szk.AUTHOR)
                src_path = os.path.join(path, szk.POVs, os.path.splitext(pov.text)[0], pov.text)
                local = os.path.join(self.local_stage, 'CBs', common)
                dest_parent = os.path.join(local, szk.AUTHOR, szk.POVs, os.path.splitext(pov.text)[0])
                try:
                    os.makedirs(dest_parent)
                    self.lgr.debug('localCopyPackageNoContext made %s' % dest_parent)
                except OSError, e: 
                    self.lgr.debug('localCopyPackageNoContext FAILED %s on make %s' % (str(e), dest_parent))
                dest_path = os.path.join(dest_parent, pov.text)
            else: 
                src_path = os.path.join(pov_path, szk.POVs, pov.text)
                dest_path = os.path.join(local, pov.text)
            if not os.path.isfile(dest_path):
                self.lgr.debug('localCopyPackageNoContext pov copy from '+src_path+' to '+dest_path)
                shutil.copy(src_path, dest_path)
            else:
                self.lgr.debug('already exists: %s' % dest_path)

        self.lgr.debug('localCopyPackageNoContext 4')
        ids = self.root.find('rules')
        if ids is not None and ids.text is not None:
            src_path = os.path.join(ids_path, szk.IDSs, ids.text)
            dest_path = os.path.join(local_ids, ids.text)
            if not os.path.isfile(dest_path):
                print 'ids copy from '+src_path+' to '+dest_path
                shutil.copy(src_path, dest_path)
            else:
                print('already exists: %s' % dest_path)
        self.lgr.debug('localCopyPackageNoContext 5')
           
    def findTeam(self, common, pov): 
        p = os.path.join(self.cfg.cb_dir, common, szk.COMPETITOR)
        path = '%s/*/*/%s' % (p, pov)
        e = glob.glob(path)
        try:
            print e[0]
        except:
            print('pov %s not found under %s' % (pov, p))
            exit(1)
        parts = e[0].split('/')
        i=0
        for p in parts:
            if p == 'competitor':
                return parts[i+1]
            i += 1


    def localCopyPackage(self, package):
        '''
        Copy from the share (nfs) to a stage local to this instance
        '''
        try:
            cb_name = self.root.find('cb_name').text
        except:
            self.lgr.error('could not find cb_name in %s' % package)
            self.hungSoDie()
        path = self.szk.pathFromName(self.cfg.cb_dir, cb_name)
        if not self.doLocalcp(path, 'CB'):
            print 'bad path: %s for CB %s not found, exiting' % (path, cb_name) 
            self.hungSoDie()
        rules = self.root.find('rules')
        if rules is not None and len(rules.text) > 0:
            ids_path = self.szk.idsPathFromName(self.cfg.cb_dir, rules.text)+'.rules'
            print "ids_path is %s" % ids_path
            self.doLocalcp(ids_path,'FILTER') 
        for pov in self.root.iter('pov'):
            common = cb_name
            if common.endswith('_MG'):
                common = common[:len(common)-3]        
            print('pov.text is %s' % pov.text)

            if pov.text.startswith('POV'):
                path = os.path.join(self.cfg.cb_dir, common, szk.AUTHOR)
                src_path = os.path.join(path, szk.POVs, os.path.splitext(pov.text)[0], pov.text)
                local = os.path.join(self.local_stage, 'CBs', common)
                dest_parent = os.path.join(local, szk.AUTHOR, szk.POVs, os.path.splitext(pov.text)[0])
                try:
                    os.makedirs(dest_parent)
                    self.lgr.debug('localCopyPackageNoContext made %s' % dest_parent)
                except OSError, e: 
                    self.lgr.debug('localCopyPackageNoContext FAILED %s on make %s' % (str(e), dest_parent))
                dest_path = os.path.join(dest_parent, pov.text)
            else: 
                team_id = None
                try:
                    team_id = self.root.find('team_id').text
                except:
                    self.lgr.debug('localCopyPackage could not find team_id in %s' % package)
                if team_id is None:
                    team_pad = self.findTeam(common, pov.text)
                else:
                    team_num = int(team_id)
                    team_pad = '%03d' % team_num
                ''' path and local may be redefined if author POV '''
                path = os.path.join(self.cfg.cb_dir, common, szk.COMPETITOR, team_pad)

                #local = os.path.join(self.local_stage, 'CBs', common)
                local = self.local_stage
                src_path = os.path.join(path, szk.POVs, pov.text)
                dest_path = os.path.join(local, pov.text)
            if not os.path.isfile(dest_path):
                self.lgr.debug('localCopyPackageNoContext pov copy from '+src_path+' to '+dest_path)
                shutil.copy(src_path, dest_path)
            else:
                self.lgr.debug('already exists: %s' % dest_path)

            #pov_path = self.szk.replayPathFromName(self.cfg.cb_dir, pov.text)
            #self.doLocalcp(pov_path, 'POV') 
        for poll in self.root.iter('poll'):
            poll_path = self.szk.replayPathFromName(self.cfg.cb_dir, poll.text)+'.xml'
            self.doLocalcp(poll_path, 'POLL') 
          
    def doOnePackage(self, encoded):
        print 'in doOnePackage ************************************'
        self.waitUntilMonitorReady()
        package_path = self.szk.addLocalPackage('some_package', encoded)
        print('packaged added')
        self.package_done_path = package_path+'/'+ szk.PACKAGE_DONE
        stat = self.szk.zk.exists(self.package_done_path, self.watchPackageDone)
        if stat is None:
            self.lgr.debug( 'doOnePackage package not done, as expected %s' % self.package_done_path)
        else:
            self.lgr.debug( 'doOnePackage package done, not expected eh?' % self.package_done_path)

    def doNext(self):
        '''
        Get the next package using the getMonitor module. And enqueue
        it using the szk.addLocalPackage() 
        '''
        timeout=30
        done = False
        # return value indicating if package will never timeout, e.g., for long debug sessions
        no_timeout = False
        while not done:
            if self.checksum is not None:
               # we ran with a one-off configuration
               #self.szk.deleteAlternateConfig()  delete in cgcMonitor?
               self.checksum = None
            # get a package, block if none ready, set nice locks on CBs
            self.package_done_path = None
            package = self.gm.getPackage(True, self.be_nice, self.single_replays, timeout)
            if package is not None:
                self.xmlParse(package)
                no_timeout = self.noTimeout()
                self.lgr.debug('packageMgr no_timeout is %r' % no_timeout)
                if self.check_monitor:
                    self.checkNeedAlternateConfig()
                self.lgr.debug('doNext, package: %s' % package)
                no_context = self.root.find('no_context')
                cb_name = self.root.find('cb_name').text
                ''' TBD hack, had used no_context, which is also a hack, that fails with vizReplay'''
                if cb_name.startswith('CB'):
                    self.localCopyPackage(package)
                else:
                    self.localCopyPackageNoContext(package)
                self.lgr.debug( 'packageMgr doNext got package ' + package)
                bs = package.encode('latin-1')
                self.lgr.debug( 'packageMgr doNext package is %s' % package)
                self.waitUntilMonitorReady()
                package_path = self.szk.addLocalPackage('some_package', bs)
                self.package_done_path = package_path+'/'+ szk.PACKAGE_DONE
                self.lgr.debug( 'in doNext, check if done at %s' % self.package_done_path)
                stat = self.szk.zk.exists(self.package_done_path, self.watchPackageDone)
                if stat is None:
                    self.lgr.debug( 'doNext, package not done, as expected')
                else:
                    self.lgr.debug( 'doNext, package done, not expected eh?')
                done = True
            elif timeout is not None:
                if not no_timeout:
                    self.lgr.debug('doNext must have timed out delete alternate config node, and see if config has changed')
                    self.szk.deleteAlternateConfig()
                    self.checkConfig()
            else:
                self.lgr.error('packageMgr call to getMontior returned None, fatal error')
                self.hungSoDie()
        return no_timeout

    def setMonitorDone(self, log):
        try:
            cb_name = self.root.find('cb_name').text
        except:
            self.lgr.error('watchPackageDone, could not find cb_name in package')
            self.hungSoDie()
        polls = self.root.findall('poll')
        povs = self.root.findall('pov')
        while len(polls) > 0 or len(povs) > 0:
            loop_polls = list(polls)
            loop_povs = list(povs)
            for poll in loop_polls:
                self.rpm.replayDone(cb_name, poll.text, log)
                    
            for pov in loop_povs:
                self.rpm.replayDone(cb_name, pov.text, log)

    def waitMonitorDone(self):
        '''
        Wait until the monitor reports all replays in the current package are done.
        Will also return if the replay node does not exist, e.g., for ad-hoc debug replays
        '''
        try:
            cb_name = self.root.find('cb_name').text
        except:
            self.lgr.error('watchPackageDone, could not find cb_name in package')
            self.hungSoDie()
        polls = self.root.findall('poll')
        povs = self.root.findall('pov')
        rules_e = self.root.find('rules')
        rules=None
        if rules_e is not None:
            rules = rules_e.text
        while len(polls) > 0 or len(povs) > 0:
            loop_polls = list(polls)
            loop_povs = list(povs)
            for poll in loop_polls:
                if not self.rpm.isReplay(cb_name, poll.text, rules) or self.rpm.isReplayDone(cb_name, poll.text, rules):
                    polls.remove(poll)
                else:
                    self.lgr.debug('waitMonitorDone poll, done: %s %s rules: %s' % (cb_name, poll.text, rules))
                    
            for pov in loop_povs:
                if not self.rpm.isReplay(cb_name, pov.text, rules) or self.rpm.isReplayDone(cb_name, pov.text, rules):
                    povs.remove(pov)
                else:
                    self.lgr.debug('waitMonitorDone, pov not done: %s %s rules is %s' % (cb_name, pov.text, rules))
            if len(polls) > 0 or len(povs) > 0:
                self.lgr.debug('waitMonitorDone not yet done, wait 2') 
                time.sleep(2)
        self.lgr.debug('waitMonitorDone all done with %s' % cb_name)
        
    def isMonitorDone(self):
        '''
        Is the monitor done with all replays in the current package?
        Will also return true if the replay node does not exist, e.g., for ad-hoc debug replays
        '''
        retval = True
        try:
            cb_name = self.root.find('cb_name').text
        except:
            self.lgr.error('isMonitorDone, could not find cb_name in package')
            self.hungSoDie()
        polls = self.root.findall('poll')
        povs = self.root.findall('pov')
        rules_e = self.root.find('rules')
        rules=None
        if rules_e is not None:
            rules = rules_e.text
        loop_polls = list(polls)
        loop_povs = list(povs)
        for poll in loop_polls:
            if not self.rpm.isReplay(cb_name, poll.text, rules) or self.rpm.isReplayDone(cb_name, poll.text, rules):
                polls.remove(poll)
            else:
                self.lgr.debug('isMonitorDone poll, done: %s %s rules: %s' % (cb_name, poll.text, rules))
                
        for pov in loop_povs:
            if not self.rpm.isReplay(cb_name, pov.text, rules) or self.rpm.isReplayDone(cb_name, pov.text, rules):
                povs.remove(pov)
            else:
                self.lgr.debug('isMonitorDone, pov not done: %s %s rules is %s' % (cb_name, pov.text, rules))
        if len(polls) > 0 or len(povs) > 0:
            self.lgr.debug('isMonitorDone not yet done')
            retval = False
        else:
            self.lgr.debug('isMonitorDone all done with %s' % cb_name)
        return retval
        

    def replayStatusOK(self, line):
        parts = line.split()
        for p in parts:
            if '=' in p:
                key, value = p.split('=')
                if key == 'RC':
                    rc = int(value)
                    if rc in range(10,14):
                        #self.setMonitorDone(line)
                        ''' for now, leave as incomplete replay so it can be tracked down easily '''
                        return False
                    else: 
                        return True
        return True

    def watchPackageDone(self, event):
        '''
        Callback invoked when a package is complete.  
        ''' 
        self.lgr.debug( 'packageMgr in watchPackageDone')
        self.lgr.debug( 'packageMgr check if done at %s' % self.package_done_path)
        if event.path == self.package_done_path and self.package_done_path is not None:
            replay_status, stat = self.szk.zk.get(event.path)

            self.lgr.debug('packageMgr yes, done, delay until monitor says done.  replay_status is %s' % replay_status)
            ''' 
            were we debugging, and not yet done with that? 
            Returns true if node exists, indicating debug session in progress.
            In which case, we call again passing this function as the watcher callback.
            '''
            auto_analysis = self.root.find('auto_analysis')
            if auto_analysis is not None or not self.rpm.checkDebugWait(None):
                if not self.cfg.no_monitor and self.replayStatusOK(replay_status):
                    self.waitMonitorDone()
                try:
                    last_slash = self.package_done_path.rfind('/')
                except:
                    self.lgr.error('watchPackageDone, package_done_path changed from under us to none? event was %s' % str(event))
                    return
                package_path = self.package_done_path[:last_slash]
                print('delete package %s' % package_path)
                self.lgr.debug('watchPackageDone, delete package %s' % package_path)
                self.szk.delLocalPackage(package_path) 
                self.package_done_path = None
                self.incCounter()
            elif not self.rpm.checkDebugWait(self.watchPackageDone):
                '''But if it had since been deleted, undo the callback. '''
                self.lgr.debug("watchPackageDone, was told to wait, now not, must have raced")
                self.rpm.checkDebugWait(None)
                self.incCounter()
            else:
                self.lgr.debug("watchPackageDone, waiting for debug to finish")
 
        elif event.path == self.szk.OUR_DEBUG_STATUS:
            self.lgr.debug('packageMgr watchPackage done for debug node %s' % self.szk.OUR_DEBUG_STATUS)
            self.incCounter()
        else:
            self.lgr.debug( 'packageMgr unexpected call to watchPackageDone')
            self.lgr.debug( event.path)

    def getReplayPath(self):
        tree = ET.parse(self.cfg.replay_master_cfg)
        root = tree.getroot()
        workspace = root.find('workspace')
        cb_dir = root.find('cb_dir')
        path = '%s%s/%s' % (workspace.text, self.instance, cb_dir.text)
        print 'getReplayPath got  '+path
        self.lgr.debug('packageMgr getReplayPath got  '+path)
        host = root.find('cb_host')
        return workspace.text, host.text, path
  
    def isPoV(self):
        '''
        Assumes singlton packages
        '''
        if root.find('pov') is not None:
            return True
        else:
            return False

    def hungSoDie(self):
        self.lgr.error('packageMgr is broken, or target seems hung, die')
        self.lgr.debug('remove replayCfg and the deleteOurStatus')
        self.szk.deleteReplayCFG(False)
        if not self.szk.deleteOurStatus():
            self.lgr.debug('hungSoDie failed to delete OurStatus')
        self.szk.stop()
        exit(1)

    def runForever(self):
        ''' 
        Use getMonitor to get all sessions from the node tree, and sessions
        defined in competitor sets and one-offs in the dbgQueue.
        The doNext() function will not return to us until there is 
        a session to run.  While waiting for consumers to finish
        processing packages (sessions), the waitCounter timeout is used to enable
        detection of hung targets.  But again, all waiting for the next
        thing to do is in the doNext().
        
        '''
        mycount = self.readCounter()
        previous_path = None
        previous_log_size = 0
        if self.instance is None:
            self.instance = 'x'
        logfile = '/mnt/cgc/logs/monitors/monitor_%s.log' % self.instance
        self.lgr.debug('packageMgr runForever, will timeout on lack of activity in %s' % logfile)
        #TBD make this timeout configurable.  Time period over which a lack of
        # new cgcMonitor.log entries will cause the putPackages to die.
        # Needs to be long if syscalls are not monitored.
        timeout = 300
        increment = 30
        elapsed = 0
        no_timeout = self.doNext()
        '''
        
        '''
        while True:
            if self.waitCounter(mycount, increment):
                mycount = self.readCounter()
                if self.package_done_path is None:
                    no_timeout = self.doNext()
            elif not no_timeout:
                ''' watch for timeout, e.g., target hung '''
                elapsed += increment
                if self.package_done_path is not None and elapsed >= timeout:
                    elapsed = 0 
                    self.lgr.debug('forever loop, previous path is %s package_done is %s' % (previous_path, self.package_done_path))
                    if previous_path is not None and self.package_done_path == previous_path:
                        # working on same package, is there log activity?
                        mycount = self.readCounter()
                        stat = self.szk.zk.exists(self.package_done_path, self.watchPackageDone)
                        if stat is None:
                            statinfo = os.stat(logfile)         
                            if statinfo.st_size == previous_log_size and not self.cfg.no_monitor:
                                # no growth, assume death
                                if not self.isMonitorDone():
                                    self.lgr.error('no growth in log, die')
                                    self.hungSoDie()
                                else:
                                    self.lgr.debug('no growth in log, but monitor is done, assume waiting for cb or pov to finish with no monitoring')
                            else:
                                previous_log_size = statinfo.st_size
                        else: 
                            # TBD remove this?
                            self.lgr.error('discovered package done in forever loop, should have been been seen by a watcher!  %s' % previous_path)
                            if not self.cfg.no_monitor:
                                self.waitMonitorDone();
                            mycount = self.readCounter()
                            no_timeout = self.doNext()                        
                    else:
                        previous_path = self.package_done_path
                else:
                    self.lgr.debug('packageMgr forever loop waiting for done, elapsed is %d' % elapsed)
