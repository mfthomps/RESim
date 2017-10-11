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
import sys
import os
import utils
import json
#DEVEL = os.getenv('CGC_DEVEL')
zkegg = "/usr/local/lib/python2.7/dist-packages"
#if DEVEL is not None and (DEVEL == 'YES' or DEVEL == '4.8'):
#    zkegg = "/usr/local/lib/python2.7/dist-packages/kazoo-1.4dev-py2.7.egg"
# TBD brute force, put both paths in there
if zkegg not in sys.path:
    sys.path.append(zkegg)
zkegg = "/usr/local/lib/python2.7/dist-packages/kazoo-1.4dev-py2.7.egg"
if zkegg not in sys.path:
    sys.path.append(zkegg)
dist_package = "/usr/lib/python2.7/dist-packages"
if dist_package not in sys.path:
    sys.path.append(dist_package)
import kazoo
import zope
from kazoo.client import KazooClient
import ConfigParser
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ElementTree
import StringIO
import re
import forensicEvents
import commands
import logging
import time
import configMgr
'''
   Utilities for managing the CGC zookeeper hierarchy
   ZooKeeper sequence numbers are 10 digits
   TBD move pure utilities to separate module
'''

AUTHOR = 'author'
AUTH = 'ATH'
COMPETITOR = 'competitor'
POVs = 'povs'
IDSs = 'idss'
POV = 'POV'
IDS = 'IDS'
POLL = 'SP'
POLLs = 'polls'
REPLAYs = 'replays'
CBs = 'cbs'
CB = 'CB'
MG = 'MG'
FORENSICS = 'forensics'
CGC_NODE = '/cgc'
FORENSICS_NODE = CGC_NODE + '/forensics'
IDA_NODE = FORENSICS_NODE + '/ida'
TEAM_SETS = FORENSICS_NODE + '/team_sets'
TEAM_SET_HINT = FORENSICS_NODE + '/team_set_hint'
CFE_QUEUE = FORENSICS_NODE + '/cfe_queue'
CFE_QUEUE_HINT = FORENSICS_NODE + '/cfe_queue_hint'
THROW_NODE = IDA_NODE + '/throw'
DBG_QUEUE = IDA_NODE + '/dbg_queue'
DBG_CLIENTS = IDA_NODE + '/dbg_clients'
POV_NODE = THROW_NODE + '/pov'
MONITORS_NODE = FORENSICS_NODE + '/monitors'
MONITORS_STATUS_NODE = MONITORS_NODE + '/status'
MONITORS_RESET_NODE = MONITORS_NODE + '/reset'
MONITORS_DEBUG_NODE = MONITORS_NODE + '/debug'
TARGETS_NODE = FORENSICS_NODE + '/targets'
CORONERS_NODE = FORENSICS_NODE + '/coroners'
CONFIG_NODE = FORENSICS_NODE + '/config'
MASTER_CONFIG_NODE = FORENSICS_NODE + '/master_config'
MASTER_DEBUG_CONFIG_NODE = FORENSICS_NODE + '/master_debug_config'
MASTER_ANALYSIS_CONFIG_NODE = FORENSICS_NODE + '/master_analysis_config'
MASTER_MSC_CONFIG_NODE = FORENSICS_NODE + '/master_msc_config'
MASTER_POV_CONFIG_NODE = FORENSICS_NODE + '/master_pov_config'
CRITICAL_NODE = FORENSICS_NODE + '/critical'
HOUSE_KEEPER_NODE = FORENSICS_NODE + '/house_keeper'
#REPLAY_CFG_NODE = MONITORS_NODE + '/replay_cfg'
#SERVICE_CFG_NODE = MONITORS_NODE + '/service_cfg'
#OUR_NODE = MONITORS_NODE + '/me'
#PACKAGES_NODE = OUR_NODE + '/packages'
VIZ_QUEUE_NODE = FORENSICS_NODE + '/viz'
CBS_NODE = FORENSICS_NODE + '/CBS'
PACKAGE_DONE = 'package_done'
SERVICE_READY = 'service_ready'
THROW = 'throw'
DONE = 'done'
CONFIG = 'config'
class szk():
    zk = None
    def __init__(self, hostname, cfg, instance='0', local_logging = False, wait_for_zk=True):
        # hack to get my IP, which is our monitor node's name       
        self.lgr = None
        self.cfg = cfg
        self.myip = utils.getMyIP()
        zkhost=None
        if os.path.isfile(cfg.zk_host_file):
            f = open(cfg.zk_host_file)
            zkhost = f.read()
            f.close()
        else:
            lookup='127.0.0.1'
            try:
                lookup=socket.gethostbyname(cfg.zk_host)
            except:
                pass
            zkhost = lookup+':'+'%d' % cfg.zk_port
        #self.zk = KazooClient(hosts=zkhost, timeout=5.0)
        print('szk __init__ try connecting to zookeeper')
        self.zk = KazooClient(hosts=zkhost)
        connected = False
        while not connected:
            try:
                self.zk.start()
                connected = True
            except:
                if not wait_for_zk:
                    break
                print('failed to connect to zookeeper, sleep 2 and try again') 
                time.sleep(2)
        if not connected:
            print('Could not connect to zk, told to not wait, return')
            self.zk = None
            return
        print('state %s' % (str(self.zk.client_state)))
        self.cfg.loadFromZookeeper(self.zk)
        self.hostname = hostname
        self.local_logging = local_logging
        self.setInstance(instance)
        ''' for auto analysis to track the package we were working on '''
        self.latest_latest = None
       
    def setInstance(self, instance):
        self.target_name = self.myip+'_'+instance
        self.OUR_NODE = MONITORS_NODE + '/'+self.target_name
        self.MY_IP = MONITORS_STATUS_NODE + '/'+self.myip
        self.OUR_STATUS = MONITORS_STATUS_NODE + '/'+self.myip+'/'+self.target_name
        self.OUR_DEBUG_STATUS = MONITORS_DEBUG_NODE + '/'+self.myip+'/'+self.target_name
        self.OUR_RESET = MONITORS_RESET_NODE + '/'+self.myip+'/'+self.target_name
        # ipc between putPackages and target-based functions, e.g., replayMaster
        self.PACKAGES_NODE = self.OUR_NODE + '/packages'
        # config data for target-based functions, e.g., replayMaster
        self.REPLAY_CFG_NODE = self.OUR_NODE +'/replay_cfg'
        self.SERVICE_CFG_NODE = self.OUR_NODE +'/service_cfg'
        # alternate location for master.cfg data for one-off runs
        self.ALTERNATE_CONFIG_NODE = self.OUR_NODE +'/alternate_cfg'
        #print 'back from zk start'
        self.zk.ensure_path(THROW_NODE)
        self.zk.ensure_path(self.PACKAGES_NODE)
        self.zk.ensure_path(TEAM_SETS)
        self.zk.ensure_path(DBG_QUEUE)
        self.zk.ensure_path(CBS_NODE)
        self.zk.ensure_path(CRITICAL_NODE)
        self.zk.ensure_path(self.MY_IP)
        result = self.zk.ensure_path(MONITORS_STATUS_NODE)
        result = self.zk.ensure_path(MONITORS_DEBUG_NODE)
        if self.hostname is not None:
            print 'hostname is '+self.hostname+' ip '+self.myip+"_"+instance
        if self.local_logging:
            print 'use local logging'
            self.setLocalLogger(instance)
 
    def reconnect(self):
        connected = False
        while not connected:
            try:
                self.zk.start()
                connected = True
            except:
                print('failed to reconnect to zookeeper, try again') 
                time.sleep(5)

    def getTargetName(self):
        return self.target_name

    def setLocalLogger(self, instance):
        print('setLocal Logger called')
        self.lgr = logging.getLogger(__name__)
        self.lgr.setLevel(logging.DEBUG)
        fh = logging.FileHandler('/mnt/cgc/logs/szk%s.log' % instance)
        fh.setLevel(logging.DEBUG)
        frmt = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(frmt)
        self.lgr.addHandler(fh)
        self.lgr.info('Start of log from szk.py (local logging)')
        self.debug('test message from self.debug')
        return fh

    def logCritical(self, record):
       node = CRITICAL_NODE+'/critical_'
       record = self.target_name + record
       try:
           #Create sequence numbered node
           node_name = self.zk.create(node, record, None, False, True, False) 
           self.debug('created critical node %s' % node_name)
       except kazoo.exceptions.NoNodeException:
           self.debug('logCritical could not create node for %s' % record)
           return None

    def getOurStatus(self):
        '''
        Get the content from this target's status node, intended to be the
        timestamp that can then be compared to that found in the reset node
        '''
        retval = None
        try:
            retval, stat = self.zk.get(self.OUR_STATUS)
        except kazoo.exceptions.NoNodeError:
            print('getOurStatus, missing status node at %s' % self.OUR_STATUS)
            self.debug('getOurStatus, missing status node at %s' % self.OUR_STATUS)
        return retval

    def getOurChecksum(self, lgr):
        '''
        Get the content from this target's reset node, intended to be the
        checksum of the current configuration.
        '''
        retval = None
        timestamp = None
        try:
            value, stat = self.zk.get(self.OUR_RESET)
            l = value.split(' ')
            if len(l) == 2:
                retval, timestamp = l
            else:
                lgr.debug('getOurCheckSum, old record format')
        except kazoo.exceptions.NoNodeError:
            print('getOurChecksum, missing reset node at %s' % self.OUR_RESET)
            lgr.debug('getOurChecksum, missing reset node at %s' % self.OUR_RESET)
        except kazoo.exceptions.ZookeeperError:
            lgr.error('getOurChecksum, zk error, state is ' % str(self.zk.state))
        return retval, timestamp

    def recordOurReset(self, record, createIt, watcher, lgr):
        '''
        Create a reset node for this monitor.  Intended to be called when
        cgcMonitor first starts, and when it re-inits due to deletion of
        the reset node.  If the node exist, we need to wait until it is 
        deleted (it is ephemeral, and may linger until zk sees the client as dead)
        '''
        print('recordOurReset')
        done = False
        while not done: 
            try:
                stat = self.zk.exists(self.OUR_RESET, None)
            except kazoo.exceptions.ZookeeperError:
                lgr.error('recordOurReset, zk error, state is ' % str(self.zk.state))
            if stat is None:
                if not createIt:
                    lgr.debug('call to recordOurReset, no zk reset node and we are not to create it')
                    return False
                try:
                    result = self.zk.create(self.OUR_RESET, value=record, ephemeral=True, makepath=True)
                    stat=self.zk.exists(self.OUR_RESET, watch=watcher)
                    if stat is not None:
                        done = True
                        lgr.debug('RecordOurReset successfull, result is %s record was %s' % (result, record))
                    else:
                        lgr.debug('recordOurReset, race? node we just created is now missing, try to recreate')
                except kazoo.exceptions.NodeExistsError:
                    print('could not create reset node at '+self.OUR_RESET+' must already exist') 
                    lgr.error('could not create reset node at '+self.OUR_RESET+' must already exist, fatal') 
                    return False 
                except kazoo.exceptions.ZookeeperError:
                    lgr.error('recordOurReset on create OurReset, zk error, state is ' % str(self.zk.state))
            else:
                lgr.debug('recordOurReset, node exists, wait for it to go away')
                print('recordOurReset, node exists, wait for it to go away')
                time.sleep(5)
        return True
                   
    def deleteOurStatus(self): 
        retval = True
        try:
            self.zk.delete(self.OUR_STATUS)
            self.debug('deleted our_status %s' % self.OUR_STATUS)
        except:
            retval = False
            self.debug('could not delete our_status %s' % self.OUR_STATUS)
        return retval

    def recordOurStatus(self, record, createIt):
        '''
        Create a status node for this monitor.  Intended to be called when
        cgcMonitor first starts.  When this node is gone, the monitor is dead.
        '''
        done = False
        while not done: 
            stat = self.zk.exists(self.OUR_STATUS, None)
            if stat is None:
                if not createIt:
                    print 'call to recordOurStatus, no zk status node and we are not to create it'
                    self.debug('call to recordOurStatus, no zk status node and we are not to create it')
                    return                    
                try:
                    result = self.zk.create(self.OUR_STATUS, value=record, ephemeral=True, makepath=True)
                    done = True
                    print('Record our status result is %s record was %s' % (result, record))
                    self.debug('Record our status result is %s record was %s' % (result, record))
                except kazoo.exceptions.NodeExistsError:
                    print('could not create status node at '+self.OUR_STATUS+' must already exist') 
                    self.debug('could not create status node at '+self.OUR_STATUS+' must already exist, fatal') 
                    return False 
            else:
                self.debug('recordOurStatus, node exists, wait for it to go away')
                print('recordOurStatus, node exists, wait for it to go away')
                time.sleep(5)
        return True
                    
    def deleteOurReset(self):
        '''
        Delete this monitors reset node. Intent is to force cgcMonitor to re-init 
        Intended to be called from putPackages and similar
        '''
        try:  
            self.zk.delete(self.OUR_RESET)
            self.debug('deleteOurReset, deleted %s' % self.OUR_RESET)
            return True
        except kazoo.exceptions.NoNodeError:
            self.debug('deleteOurReset, node already gone')
            return False

    def isReplayDone(self, cb, replay):
        retval = True
        path = CBS_NODE+'/'+cb+'/'+replay
        if not self.isDone(path):
            retval = False
        return retval

    def stripLogTail(self, log):
        retval, dum = log.split('</replay_log>')
        return retval


        
    def debug(self, msg):
        if self.lgr is not None:
            self.lgr.debug('***FROM SZK:'+msg)
        else:
            print('no debugger, msg: '+msg)
       
    ''' add a work package to be consumed by a network host & pov thrower '''
    def addLocalPackage(self, name, data):
        new_node = self.zk.create(self.PACKAGES_NODE+"/"+name, data, None, False, True, False) 
        return new_node


    def getLatestLocalPackage(self, lgr):
        ''' intended for panic use by monitor if replay fails without exec ''' 
        children = self.zk.get_children(self.PACKAGES_NODE)
        if len(children) == 0:
            lgr.debug('getLatestLocalPackage found no packages')
            return None
        latest = sorted(children, reverse=True)[0]
        node = self.PACKAGES_NODE+'/'+latest
        retval = None
        try:
            value, stat = self.zk.get(node)
        except kazoo.exceptions.NoNodeError:
            lgr.error('getLatestLocalPackage, no package at %s' % node)
            return None
       
        self.latest_latest = latest 
        lgr.debug('getLatestLocalPackage, now parse xml')
        try:
            retval = ET.fromstring(value)
        except:
            lgr.error('getLatestLocalPackage could not parse: %s' % value)
        return retval

    def setLatestLocalPackageDone(self, lgr):
        if self.latest_latest is None:
            lgr.error('setLatestLocalDone called, but no latest package retrieved')
            return
        ''' intended for by monitor with auto analysis ''' 
        node = self.PACKAGES_NODE+'/'+self.latest_latest+'/'+PACKAGE_DONE
        try:
           self.zk.create(node)
        except kazoo.exceptions.NoNodeError:
            lgr.error('setLatestLocalPackageDone, no package at %s' % node)
            return None
        
    def delLocalPackage(self, name):
        self.zk.delete(name, recursive=True)

    def stop(self):
        if self.zk is not None:
            self.zk.stop()

    class packageStatus():
        def __init__(self, name, ready, done):
            self.name = name
            self.ready = ready 
            self.done = done

    def listPackages(self, instance, only_undone):
        target_name = self.myip+'_'+instance
        target_node = MONITORS_NODE + '/'+target_name
        packages_node = target_node + '/packages'
        try:
            children = self.zk.get_children(packages_node)
        except kazoo.exceptions.NoNodeError:
            print('no package node at %s' % packages_node)
            return
        ps_list = []
        print 'list packages look in '+packages_node
        for child in children:
                print 'checking package %s' % child
                
                done = True
                ready = True
                done_path = packages_node+'/'+child+'/'+PACKAGE_DONE
                stat = self.zk.exists(done_path, None)
                if stat is None:
                    done = False
                service_ready_path = packages_node+'/'+child+'/'+SERVICE_READY
                stat = self.zk.exists(service_ready_path, None)
                if stat is None:
                    ready = False
                if not done or not ready:
                    ps = self.packageStatus(child, ready, done)
                    ps_list.append(ps)
                    print 'undone package is %s service_ready: %r  package_done: %r' % (child,
                         ready, done)
                elif not only_undone:
                    print 'package %s is done' % child
        return ps_list

    def cleanPackages(self):
        children = self.zk.get_children(self.PACKAGES_NODE)
        print 'look for packages at '+ self.PACKAGES_NODE
        for child in children:
            self.zk.delete(self.PACKAGES_NODE+'/'+child, recursive=True)

    def getNicePath(self, path, queue_name):
        return path+"/"+queue_name+"_nice"

    def getLockPath(self, path, queue_name):
        return path+"/"+queue_name+"_lock"

    def isLock(self, node):
        if '_nice' in node or '_lock' in node:
            return True
        else:
            return False

    def hasNiceLocks(self, cb_path):
        retval = []
        children = self.zk.get_children(cb_path)
        for child in children:
            if "_nice" in child:
                retval.append(child)
        return retval
        
    def hasHardLocks(self, path):
        retval = []
        children = self.zk.get_children(path)
        for child in children:
            if "_lock" in child:
                retval.append(child)
        return retval

    def hasThisHardLock(self, path, queue_name):
        drone = None
        timestamp = None
        lock_path = self.getLockPath(path, queue_name)
        try:
           #print 'look for this hard lock '+lock_path
           value, stat = self.zk.get(lock_path)
           parts = value.strip().split(' ')
           drone = parts[0]
           timestamp = parts[1]
        except:
           pass
        return drone, timestamp
     
    def getNiceLock(self, cb_path, queue_name):
        nice_path = self.getNicePath(cb_path, queue_name)
        retval = False
        try:
           self.zk.create(nice_path, self.hostname, ephemeral=True)
           retval = True
           #print 'created nice lock at %s' % nice_path
        except kazoo.exceptions.NodeExistsError:
           value, stat = self.zk.get(nice_path)
           if value != self.hostname:
               print 'failed to get lock at %s' % nice_path
               pass
           else:
               retval = True
        return retval

    def cbReleaseNiceLock(self, cb, queue_name):
        cb_path = CBS_NODE+"/"+cb
        nice_path = self.getNicePath(cb_path, queue_name)
        #if self.lgr is not None:
        #    self.lgr.debug("cbReleaseNiceLock path to release is %s, queue %s" % (nice_path, queue_name))
        try:
            self.zk.delete(nice_path)
            #self.lgr.debug("cbReleaseNiceLock did release ")
        except kazoo.exceptions.NoNodeError:
            pass
            #self.lgr.debug("cbReleaseNiceLock COULD NOT FIND path %s, queue %s" % (nice_path, queue_name))
            #print 'unexpected error deleting nice lock %s' % nice_path

    def getHouseKeepingLock(self, checksum):
        has_lock = None
        retval = False
        try:
           has_lock = self.hostname+':'+checksum
           self.zk.create(HOUSE_KEEPER_NODE, has_lock, ephemeral=True)
           retval = True
           #print 'created nice lock at %s' % nice_path
        except kazoo.exceptions.NodeExistsError:
           has_lock, stat = self.zk.get(HOUSE_KEEPER_NODE)
        return retval, has_lock

    def releaseHouseKeepingLock(self):
        try:
            self.zk.delete(HOUSE_KEEPER_NODE)
        except kazoo.exceptions.NoNodeError:
            pass


    def hasMasterCfg(self):
        retval = False
        try:
            stat = self.zk.exists(MASTER_CONFIG_NODE)
            if stat is not None:
                retval = True
        except kazoo.exceptions.NoNodeError:
            pass
        return retval

    def nodeFromConfigName(self, config_name):
        f = None
        node = None
        if config_name == "debug":
            node = MASTER_DEBUG_CONFIG_NODE
            f = self.cfg.master_debug_cfg
        elif config_name == "analysis":
            node = MASTER_ANALYSIS_CONFIG_NODE
            f = self.cfg.master_analysis_cfg
        elif config_name == "msc":
            node = MASTER_MSC_CONFIG_NODE
            f = self.cfg.master_msc_cfg
        elif config_name == "pov":
            node = MASTER_POV_CONFIG_NODE
            f = self.cfg.master_pov_cfg
        elif config_name == "master":
            node = MASTER_CONFIG_NODE
            f = self.cfg.master_cfg
        else:
            print('unknown configuration: %s, fatal' % config_name)
            exit(1)
        return node, f
       
    def alternateConfigFromName(self, config_name):
        node, dum = self.nodeFromConfigName(config_name)
        retval = False
        try:
            value, stat = self.zk.get(node)
            self.putAlternateConfig(value) 
            print('alternateConfigFromName config name %s loaded %s to alt config node' % (config_name, node))
            retval = True
        except kazoo.exceptions.NoNodeError:
            print('getAlternateConfigFromName no %s config' % config_name)
        return retval
        
    def deleteAlternateConfig(self):
        retval = 0
        try:
            self.zk.delete(self.ALTERNATE_CONFIG_NODE)
        except:
            retval = -1
            pass
        return retval

    def getAlternateConfig(self):
        retval = None
        try:
            retval, stat = self.zk.get(self.ALTERNATE_CONFIG_NODE)
            print('getAlternateConfig, altnerate configu exists')
        except kazoo.exceptions.NoNodeError:
            print('getAlternateConfig no alternate config')
            pass
        except kazoo.exceptions.SessionExpiredError:
            self.debug('getAlternateConfig, zk session expired')
            connected = False
            try:
                self.zk.start()
                connected = True
            except:
                print('getAlternateConfigfailed to connect to zookeeper') 
                return None
        
            try:
                retval, stat = self.zk.get(self.ALTERNATE_CONFIG_NODE)
                print('getAlternateConfig, 2nd altnerate configu exists')
            except kazoo.exceptions.NoNodeError:
                print('getAlternateConfig 2nd no alternate config')
                pass
                
        return retval            

    def putAlternateConfig(self, config):
        '''
        Write a given master configuration to the ALTERNATE_CONFIG_NODE, which should not
        yet exist.
        This is intended for use by one-off uses of putMonitor, e,g., to debug a binary
        '''
        try:
            self.zk.create(self.ALTERNATE_CONFIG_NODE, config, ephemeral=True)
            self.debug('putAlternateConfig, node created')
        except kazoo.exceptions.NodeExistsError:
            try:
                was = self.zk.get(self.ALTERNATE_CONFIG_NODE)
                if config == was:
                    self.debug('putAlternateConfig node with desired config already exists, if from previous run, we are doomed in that it will be deleted.  Delete and recreate?')

                return
            except kazoo.exceptions.NoNodeError:
                pass
            print('putAlternateConfig unexpectedly found alternate config node at %s exiting' % self.ALTERNATE_CONFIG_NODE)
            self.debug('putAlternateConfig unexpectedly found alternate config node at %s exiting' % self.ALTERNATE_CONFIG_NODE)
            exit(1)

        
    def getCBs(self): 
        stat = self.zk.exists(CBS_NODE)
        if stat is None:
            return None
        children = self.zk.get_children(CBS_NODE)
        return children

    def getReplays(self, cb):
        cb_path = CBS_NODE+'/'+cb
        stat = self.zk.exists(cb_path)
        if stat is None:
            return None
        children = self.zk.get_children(cb_path)
        return children
        

    def cleanCBs(self):
        stat = self.zk.exists(CBS_NODE)
        if stat is None:
            return
        children = self.zk.get_children(CBS_NODE)
        for child in children:
            self.zk.delete(CBS_NODE+'/'+child, recursive=True)

    def cleanMonitors(self):
        stat = self.zk.exists(MONITORS_NODE)
        if stat is None:
            return
        children = self.zk.get_children(MONITORS_NODE)
        for child in children:
            self.zk.delete(MONITORS_NODE+'/'+child, recursive=True)

    def cleanCritical(self):
        stat = self.zk.exists(CRITICAL_NODE)
        if stat is None:
            return
        children = self.zk.get_children(CRITICAL_NODE)
        for child in children:
            self.zk.delete(CRITICAL_NODE+'/'+child, recursive=True)
        

    def isLocked(self, path, queue_name):
        drone = None
        timestamp = None
        locked, ts = self.hasThisHardLock(path, queue_name)
        if locked is not None:
            drone = locked
            timestamp = ts
        return drone, timestamp

    def replayStatus(self, path, current_time):
        retval = ''
        who, timestamp = self.isLocked(path, FORENSICS)
        if self.isDone(path):
            if who is not None:
                retval = 'Done (%s)' % who
            else:
                drone = self.getLatestLogEntry(path, 'drone')
                retval = 'Done (by %s)' % drone
        else:
            if who is not None:
                delta = 0
                try:
                    then = float(timestamp)
                    delta = current_time - then
                except:
                    print('could not get float from %s' % timestamp)
                    pass 
                retval = 'Locked by %s at %.0f' % (who, delta)
        return retval

    def checkDups(self, cb, replay, status, lock_set):
        if status.startswith("Locked"):
            dum, dum, who = status.split(" ")
            if who in lock_set:
                print('***************ERROR******** one target holds two locks***********')
            else:
                lock_set.append(who)

    def listIncompleteCBs(self, verbose):
        '''      
        List incomplete replays.  If verbose, list them all, otherwise just list the locked ones.
        '''
        current_time = time.time()
        children = self.zk.get_children(CBS_NODE)
        children.sort()
        print '%d CBs list:' % len(children)
        count=0
        for child in children:
            cb_node = CBS_NODE+'/'+child
            value, stat = self.zk.get(cb_node)
            hint_list = value.strip().split(' ')
            hint_list = filter(None, hint_list)
            cb_children = self.zk.get_children(cb_node)
            replay_count = 0
            for replay in cb_children:
                if self.isPoV(replay) or self.isPoll(replay):
                    replay_count += 1
            if replay_count == len(hint_list):
                #print('%s is done' % child)
                continue 
            for replay in cb_children:
                if replay in hint_list:
                    continue
                #print('%s not in hint_list' % replay)
                if self.isPoV(replay) or self.isPoll(replay):
                    path = cb_node+'/'+replay
                    status = self.replayStatus(path, current_time)
                    if verbose:
                        if not status.startswith('Done'):
    		            print '%s \t%s \t%s' % (child, replay, status)
                            count += 1
                    else:
                        if "Locked" in status:
    	                    print '%s \t%s \t%s' % (child, replay, status)
                            count += 1
        print('%d items' % count)



    def listCBs(self, verbose, incomplete):
        current_time = time.time()
        lock_set = []
        children = self.zk.get_children(CBS_NODE)
        children.sort()
        print '%d CBs list:' % len(children)
        for child in children:
            cb_node = CBS_NODE+'/'+child
            nice_locks = self.hasNiceLocks(cb_node)
            nstring = ''
            for nice in nice_locks:
                nstring = nstring+nice+' '
            if not incomplete:
                print '\t%s \t%s' % (child, nstring)
            if verbose:
                cb_children = self.zk.get_children(cb_node)
                # crude sort by type pov/poll
                for replay in cb_children:
                    if self.isPoV(replay):
                        path = cb_node+'/'+replay
                        status = self.replayStatus(path, current_time)
                        if not incomplete or not status.startswith('Done'):
                            if incomplete:
			        print '%s\t%s\t %s' % (child, replay, status)
                                self.checkDups(child, replay, status, lock_set)
                            else:
			        print '\t\t%s\t %s' % (replay, status)
                for replay in cb_children:
                    if self.isPoll(replay):
                        path = cb_node+'/'+replay
                        status = self.replayStatus(path, current_time)
                        if not incomplete or not status.startswith('Done'):
                            if incomplete:
			        print '%s\t%s\t %s' % (child, replay, status)
                                self.checkDups(child, replay, status, lock_set)
                            else:
			        print '\t\t%s\t %s' % (replay, status)

    ''' CB binaries all end with a _xx where xx indicates which of N binaries
        Strip off that bit to get the common name
        it is part of a multiprocess CB service (e.g., ends with _1).
    ''' 
    def cbFromComm(self, cb_comm):
        comm = utils.getCommonName(cb_comm)
        suffix = utils.getCBSuffix(cb_comm)
        return comm, suffix
    
    '''  Read the configuration data (e.g., text section address) from a CB node '''
    def getCBConfig(self, comm, cb_name=None):
       
        if comm.endswith('.rcb'):
            cb = comm
        else:
            cb, dumm = self.cbFromComm(comm)
           
        no_num = utils.rmBinNumFromName(cb)
        ''' tbd, will break on multibinary? '''
        if (no_num.endswith('01') or no_num.endswith('_MG')) and comm.endswith('_01'):
            ''' special case, running ida client with ref '''
            config_path = CBS_NODE+'/'+no_num+'/'+CONFIG+'/'+comm
        else: 
            path_name = cb_name 
            if cb_name is None:
                path_name = no_num
            config_path = CBS_NODE+'/'+path_name+'/'+CONFIG+'/'+comm
        print 'config path is %s' % config_path
        value = None
        try:
            value, stat = self.zk.get(config_path)
        except kazoo.exceptions.NoNodeError:
            print 'in getCBConfig, no node for %s config_path of %s ' % (cb, config_path)
        return value
        
    def listAllReplays(self):
        children = self.zk.get_children(CBS_NODE)
        children.sort()
        for child in children:
            self.listReplays(child, True)

    def listAllPov(self):
        children = self.zk.get_children(CBS_NODE)
        children.sort()
        team_sets = []
        for cb in children:
            cb_path = CBS_NODE+'/'+cb
            children = self.zk.get_children(cb_path)
            did_one = False
            for replay in children:
                if self.isPoV(replay):
                    #self.showLog(cb_path, replay)
                    entries, raw = self.getLog(cb_path, replay)
                    for entry in entries:
                        if 'POV' in entry['display_event'] or 'USER_SIGSEGV' in entry['display_event']:
                            #self.showLog(cb_path, replay)
                            did_one=True
                            team_sets.append(entry['team_set'])
                else:
                    entries, raw = self.getLog(cb_path, replay)
                    break_out=False
                    for entry in entries:
                        if 'LAUNCH' in entry['display_event'] or 'SIGSEGV' in entry['display_event']:
                            #if did_one:
                            #    print('strike that, segv on polls as well')
                            break_out = True
                            break
                    if break_out:
                        if entry['team_set'] in team_sets:
                            team_sets.remove(entry['team_set'])
                        break
        return team_sets                    
            
 
    def listOneReplay(self, cb, replay):
        cb_path = CBS_NODE+'/'+cb
        path = cb_path+'/'+replay
        columns = 'name / datetime \t\ttime \tc_sys \tr_sys \tctick \tcutick \tc_flt \tr_flt \trtc \tmpb \tcfg \tevent '
        ''' extra node for config '''
        print '%s' % (columns)
        self.showLog(cb_path, replay)
 
    ''' list pov or polls of a given cb, optionally displaying the logs ''' 
    def listReplays(self, cb, show_log, raw=False):
        current_time = time.time()
        print 'look for cb %s' % cb
        cb_path = CBS_NODE+'/'+cb
        try:
            value, stat = self.zk.get(cb_path)
            children = self.zk.get_children(cb_path)
        except kazoo.exceptions.NoNodeError:
            print 'no node found for %s' % cb
            return
        hints = value.strip().split(' ')
        hints = filter(None, hints)
        children.sort()
        if show_log:
            if not raw:
                columns = 'name rules / datetime \t\ttime \tc_sys \tr_sys \tctick \tcutick \tc_flt \tr_flt \trtc \tmpb \tcfg \tevent '
                ''' extra node for config '''
                print '%d replays for %s \n  %s' % (len(children)-1, cb, columns)
        replay_count = 0
        for child in children:
            if self.isPoV(child) or self.isPoll(child):
                replay_count += 1
                if not show_log:
                    path = cb_path+'/'+child
                    status = self.replayStatus(path, current_time)
                    rules_str = ''
                    rules = self.getLatestLogEntry(path, 'rules')
                    if rules is not None:
                        rules_str = rules
                    print('replay: %s %s\t%s' % (child, rules, status))
                    '''
                    if self.isDone(path):
                        lstring = 'done'
                    else:
                        locks = self.hasHardLocks(cb_path+'/'+child)
                        lstring = ''
                        for lock in locks:
                            lstring = lstring+lock+' '
                    print '%s\t%s' % (child, lstring)
                    '''
                else:
                    if raw:
                        self.showRawLog(cb_path, child)
                    else:
                        self.showLog(cb_path, child)
            elif child != CONFIG and not self.isLock(child):
               print 'unknown node is %s' % child
        #print('%d replays, %d appear done' % (replay_count, len(hints)))
           
    ''' list all replacement binaries that have been polled by a given service poll ''' 
    def listReplacements(self, look_for_replay):
        children = self.zk.get_children(CBS_NODE)
        children.sort()
        columns = 'name / datetime \t\ttime \tc_sys \tr_sys \tctick \tcutick \tc_flt \tr_flt \trtc \tevent '
        ''' extra node for config '''
        print 'replacements polled by %s \n  %s' % (look_for_replay, columns)
        for child in children:
            cb_path = CBS_NODE+'/'+child
            replays = self.zk.get_children(cb_path)
            for replay in replays:
                if replay == look_for_replay:
                    print child
                    self.showLog(cb_path, replay)
 
    ''' format a value to use units M (mega) or K (kilo) ''' 
    def formatMorK(self, value):
        if value < 1000000:
            return value
        elif value < 100000000:
            value = value/1000
            return '%dK' % value
        else:
            value = value/1000000
            return '%dM' % value

    def intNoneZero(self, s):
        if s is None:
            return 0
        return int(s)

    def numCBs(self):
        children = self.zk.get_children(CBS_NODE)
        return len(children)

    def numPoVs(self):
        pov_count = 0 
        done_count = 0
        cbs = self.zk.get_children(CBS_NODE)
        for cb in cbs:
            print 'cb is %s' % cb
            cb_path = CBS_NODE+'/'+cb
            value, stat = self.zk.get(cb_path)
            hint_list = value.strip().split(' ')
            hint_list = filter(None, hint_list)
            children = self.zk.get_children(cb_path)
            for child in children:
                if self.isPoV(child):
                    #print '    pov is %s' % child
                    pov_count += 1
                    if child in hint_list:
                        done_count += 1
        return pov_count, done_count

    def numPolls(self):
        poll_count = 0 
        done_count = 0
        cbs = self.zk.get_children(CBS_NODE)
        for cb in cbs:
            cb_path = CBS_NODE+'/'+cb
            value, stat = self.zk.get(cb_path)
            hint_list = value.strip().split(' ')
            hint_list = filter(None, hint_list)
            children = self.zk.get_children(cb_path)
            polls_for_CB = 0
            polls_done = 0
            for child in children:
                if self.isPoll(child):
                    #print '    poll is %s' % child
                    polls_for_CB += 1
                    if child in hint_list:
                        polls_done += 1
            poll_count += polls_for_CB
            done_count += polls_done
            print('cb is %s, polls: %d done: %d' % (cb, polls_for_CB, polls_done))
        return poll_count, done_count

    def listUnlockedReplays(self, queue_name): 
        my_lock = queue_name + '_lock'
        children = self.zk.get_children(CBS_NODE)
        for cb in children:
            if self.isCB(cb):
                cb_path = CBS_NODE+'/'+cb
                replays = self.zk.get_children(cb_path)
                for replay in replays:
                    if self.isPoV(replay):
                        locks = self.hasHardLocks(cb_path+'/'+replay)
                        if not my_lock in locks:
                            print '%s:%s unlocked' % (cb, replay)
                    elif self.isPoll(replay):
                        locks = self.hasHardLocks(cb_path+'/'+replay)
                        if not my_lock in locks:
                            print '%s:%s unlocked' % (cb, replay)
                   
        
    def dumdum(self):
        self.lgr("in dumdum")
 
    ''' remove any locks held by a given target, unless the replay is complete ''' 
    def removeLocks(self, queue_name, target_name):
        self.debug('in removeLocks for %s' % target_name)
        children = self.zk.get_children(CBS_NODE)
        for cb in children:
            if self.isCB(cb):
                cb_path = CBS_NODE+'/'+cb
                replays = self.zk.get_children(cb_path)
                removed_stale_lock = False
                for replay in replays:
                    path = cb_path+'/'+replay
                    done_path = path+'/'+DONE
                    stat = self.zk.exists(done_path, None)
                    if stat is None:
                        # replay is not done, is it locked?
                        #if self.lgr is not None:
                        #    self.lgr.debug('is this locked? %s' % self.getLockPath(path, queue_name))
                        lock, timestamp = self.hasThisHardLock(path, queue_name)
                        if lock is not None:
                             self.debug('lock held by %s' % lock)
                             if target_name == 'all' or lock == target_name:
                                 lock_path = self.getLockPath(path, queue_name)
                                 print 'removing stale lock at '+lock_path+' from deceased: '+target_name
                                 self.zk.delete(lock_path)
                                 removed_stale_lock = True
                                 self.debug('removing stale lock at '+lock_path+' from deceased" '+target_name)
                            
                if removed_stale_lock:
                    self.cbReleaseNiceLock(cb, queue_name)
                    
 
    def isCB(self, cb):
        if cb.startswith('CB') or cb.endswith('.rcb'):
            return True
        else:
            return False

    def isPoll(self, poll):
        if poll.startswith(POLL):
            return True
        else:
            return False

    def isPoV(self, pov):
        if ':' in pov:
            pov = pov.split(':')[0]
        if pov.startswith(POV) or pov.endswith('.pov'):
            return True
        else:
            return False

    def isNiceLocked(self, cb_path, queue_name):
        retval = False
        nice_path = self.getNicePath(cb_path, FORENSICS)
        try:
            stat = self.zk.exists(nice_path)
            if stat is not None:
                value, stat = self.zk.get(nice_path)
                if value != self.hostname:
                    retval = True
                else:
                    #print 'I (%s) had the nice lock at %s' % (self.hostname, nice_path)
                    pass
        except kazoo.exceptions.ZookeeperError:
            print('isNiceLocked, unexpected zk error %s' % str(self.zk.state))
            self.debug('isNiceLocked, unexpected zk error %s' % str(self.zk.state))
            pass
        return retval

    def getHardLock(self, path, queue_name):
        lock_path = self.getLockPath(path, queue_name)
        retval = False
        #print 'getHardLock '+lock_path
        self.debug('getHardLock for %s' % lock_path)
        print('getHardLock for %s' % lock_path)
        if self.zk.exists(lock_path) is None:
            try:
               current_time = time.time()
               record = self.target_name+' '+str(current_time)
               result = self.zk.create(lock_path, record, ephemeral=True)
               retval = True
               self.debug('getHardLock created at %s' % result)
               print('getHardLock created at %s' % result)
               #print('got hard lock '+lock_path)
            except kazoo.exceptions.NodeExistsError:
               self.debug('getHardLock, tried to create, but lock node already exists at %s' % lock_path)
               print('getHardLock, tried to create, but lock node already exists at %s' % lock_path)
               pass
        else:
            self.debug('getHardLock, lock node already exists at %s' % lock_path)
            print('getHardLock, lock node already exists at %s' % lock_path)
        return retval

    def getOrigCB(self, cb):
        parts = cb.split('_')
        return parts[0]+'_'+parts[1]

    # get a list of all PoV names for a given CB
    def getAllPoVs(self, cb):
        retval = []
        povs = self.zk.get_children(CBS_NODE+'/'+cb)
        for pov in povs:
            if self.isPoV(pov):
                retval.append(pov)
        return retval

    # get a list of all Poller names for a given CB
    def getAllPolls(self, cb):
        retval = []
        polls = self.zk.get_children(CBS_NODE+'/'+cb)
        for poll in polls:
            if self.isPoll(poll):
                retval.append(poll)
        return retval

    def pathFromName(self, cb_dir, common):
        relative = utils.pathFromCommon(common)
        if relative is None:
            self.debug('szk pathFromName, could not get path from %s' % common)
            return None
        path = os.path.join(cb_dir, relative, os.path.basename(relative))
        return path
        

    ''' get a full path of a POV or poll file from its name '''
    def replayPathFromName(self, cb_dir, name):
        root, ext = os.path.splitext(name)
        print 'root '+root+'  from name '+name
        items  = root.split('_')
        if items is None or len(items) < 4:
            print('replayPathFrom name got bad name: %s' % name)
            return None
        print 'in replayPathFromName, %d items, first is %s' % (len(items), items[0])
        path = None
        cb_name = items[1]+'_'+items[2] 
        if items[0].startswith(POV):
            if items[3] == AUTH:
                path = cb_dir+'/'+cb_name+'/'+AUTHOR+'/'+POVs+'/'+root+'/'+name
            else:
                path = cb_dir+'/'+cb_name+'/'+COMPETITOR+'/'+items[3]+'/'+POVs+'/'+root+'/'+name
        elif items[0].startswith(POLL):
                path = cb_dir+'/'+cb_name+'/'+AUTHOR+'/'+POLLs+'/'+root+'/'+name
        else:
            print 'bad POV/POLL name, should start with "%s" or "%s" %s' % (POV, POLL, name)
            return None

        return path

    ''' get a full path of a POV or poll file from its name '''
    def idsPathFromName(self, cb_dir, name):
        root, ext = os.path.splitext(name)
        print 'root '+root+'  from name '+name
        if root.startswith('GENERIC'):
            path = os.path.join(cb_dir,'../generic-filters', name)
        else:
            items  = root.split('_')
            if items is None or len(items) < 4:
                print('idsPathFromName name got bad name: %s' % name)
                return None
            print 'in idsPathFromName, %d items, first is %s' % (len(items), items[0])
            print items
            path = None
            cb_name = items[1]+'_'+items[2] 
            if items[0].startswith(IDS):
                if items[3] == AUTH:
                    path = cb_dir+'/'+cb_name+'/'+AUTHOR+'/'+IDSs+'/'+name
                else:
                    path = cb_dir+'/'+cb_name+'/'+COMPETITOR+'/'+items[3]+'/'+IDSs+name
            else:
                print 'bad IDS name, should start with "%s" %s' % (IDS, name)
                return None

        return path

    ''' get a full path of a POV or poll file from its name '''
    def replayPathFromNameArtifacts(self, cb_dir, name, common):
        root, ext = os.path.splitext(name)
        print 'root '+root+'  from name '+name
        items  = root.split('_')
        print 'in replayPathFromName, %d items, first is %s' % (len(items), items[0])
        path = None, None
        cb_name = items[1] 
        if items[0].startswith(POV):
            if items[3] == AUTH:
                #path = self.cb_dir+'/'+cb_name+'/'+AUTHOR+'/'+REPLAYs+'/'+root+'/'+name
                path = os.path.join(cb_dir, cb_name, AUTHOR, common, REPLAYs, root, name)
            else:
                #path = self.cb_dir+'/'+cb_name+'/'+COMPETITOR+'/'+items[2]+'/'+REPLAYs+'/'+root+'/'+name
                path = os.path.join(cb_dir, cb_name, COMPETITOR, items[3], REPLAYs, root, name)
        elif items[0].startswith(POLL):
                #path = self.cb_dir+'/'+cb_name+'/'+AUTHOR+'/'+REPLAYs+'/'+root+'/'+name
                path = os.path.join(cb_dir, cb_name, AUTHOR, REPLAYs, root, name)
        else:
            print 'bad POV/POLL name, should start with "%s" or "%s" %s' % (POV, POLL, name)
            return None, None

        return path, cb_name

    def isDone(self, replay_path, watch=None):
        retval = False
        done_node = replay_path+'/'+DONE
        stat = self.zk.exists(done_node, watch=watch)
        if stat is not None:
            retval = True
        return retval

    def getLatestLogEntry(self, path, param):
        retval = None
        if self.isDone(path):
            value, stat = self.zk.get(path+'/'+DONE)
            #print value
            log_file = StringIO.StringIO(value)
            tree = ET.parse(log_file)
            entries = tree.findall('replay_entry')
            data = []
            for entry in entries:
                key = entry.findtext("time_start")
                data.append((key, entry))
            data.sort()
            if len(data) > 0:
                latest = data[len(data)-1]
                retval = latest[1].findtext(param)
        return retval

    def safeInt(self, log_entry, entry, field):
        value = entry[1].findtext(field)
        if value is not None:
            log_entry[field] = int(value)
        else:
            #self.debug('safeInt found none in %s' % field)
            log_entry[field] =0

    def safeFloat(self, log_entry, entry, field):
        value = entry[1].findtext(field)
        if value is not None:
            log_entry[field] = float(value)
        else:
            #self.debug('safeInt found none in %s' % field)
            log_entry[field] =0.0

    '''
        Read one or more log entries from a replay done node and parse out some key fields.
        Returns the raw entries and a parsed version of the entries (as a dictionary)
    '''
    def getLog(self, cb_path, child, watch=None):
        #print 'show log'
        child_node = cb_path+'/'+child
        return_entries = []
        return_raw = []
        entries = None
        if self.isDone(child_node):
            team_set = None
            replay_json, stat = self.zk.get(child_node)
            try:
                rj = json.loads(replay_json)
                team_set = rj[1]
            except:
                pass
            value, stat = self.zk.get(child_node+'/'+DONE, watch)
            #print value
            log_file = StringIO.StringIO(value)
            tree = ET.parse(log_file)
            entries = tree.findall('replay_entry')
            data = []
            for entry in entries:
                key = entry.findtext("time_start")
                data.append((key, entry))
            data.sort()
            for entry in data:
                return_raw.append(ET.tostring(entry[1]))
                log_entry = {} 
                log_entry['name'] = entry[1].findtext('replay_name')
                log_entry['config'] = entry[1].findtext('config_checksum')
                log_entry['sys_config'] = entry[1].findtext('sys_config')
                #log_entry['duration'] = float(entry[1].findtext('duration'))
                self.safeFloat(log_entry, entry, 'duration')
                #self.safeInt(log_entry, entry, 'replay_cycles')
                #log_entry['replay_cycles'] = int(entry[1].findtext('replay_cycles'))
                #self.safeInt(log_entry, entry, 'replay_user_cycles')
                #log_entry['replay_user_cycles'] = int(entry[1].findtext('replay_user_cycles'))
                #log_entry['replay_faults'] = int(entry[1].findtext('replay_faults'))
                self.safeInt(log_entry, entry, 'replay_faults')
                self.safeInt(log_entry, entry, 'replay_sys_calls')
                self.safeInt(log_entry, entry, 'poll_fail')
                #log_entry['replay_calls'] = int(entry[1].findtext('replay_sys_calls'))
                cb_entries = entry[1].findall('cb_entry')
                log_entry['cb_calls'] = 0
                log_entry['cb_wrote'] = 0
                log_entry['cb_read'] = 0
                log_entry['cb_cycles'] = 0
                log_entry['cb_user_cycles'] = 0
                log_entry['cb_faults'] = 0
                log_entry['wall_time'] = 0
                log_entry['untouched_blocks'] = 0
                for cb_entry in cb_entries:
                    log_entry['cb_calls'] += self.intNoneZero(cb_entry.findtext('cb_sys_calls'))
                    log_entry['cb_wrote'] += self.intNoneZero(cb_entry.findtext('cb_bytes_wrote'))
                    log_entry['cb_read'] += self.intNoneZero(cb_entry.findtext('cb_bytes_read'))
                    log_entry['cb_cycles'] += self.intNoneZero(cb_entry.findtext('cb_cycles'))
                    log_entry['cb_user_cycles'] += self.intNoneZero(cb_entry.findtext('cb_user_cycles'))
                    log_entry['cb_faults'] += self.intNoneZero(cb_entry.findtext('cb_faults'))
                    log_entry['untouched_blocks'] += self.intNoneZero(cb_entry.findtext('untouched_blocks'))
                    try:
                        cb_wall_time = float(cb_entry.findtext('cb_wallclock_duration'))
                        log_entry['wall_time'] = max(cb_wall_time, log_entry['wall_time'])
                    except:
                        #print 'got garb for cb_wallclock_duration: %s' % cb_entry.findtext('cb_wallclock_duration')
                        pass
                log_entry['display_event'] = ''
                events = entry[1].findall('event')
                log_entry['is_score'] = False
                log_entry['protected_access'] = []
                for event in events:
                    event_type = int(event.findtext('event_type')) 
                    if forensicEvents.isScore(event_type):
                        log_entry['is_score'] = True
                    if event_type == forensicEvents.USER_MEM_LEAK:
                        # tracking access to magic page
                        json_string = event.findtext('descrip')
                        log_entry['protected_access'].append(json_string)
                    else:
                        #print 'found event %d' % event_type
                        log_entry['display_event'] = log_entry['display_event']+' '+forensicEvents.stringFromEvent(event_type)
                log_entry['replay'] = entry[0] 
                log_entry['drone'] = entry[1].findtext('drone')
                log_entry['time_start'] = entry[1].findtext('time_start')
                log_entry['time_end'] = entry[1].findtext('time_end')
                log_entry['load_fail'] = entry[1].find('load_fail')
                log_entry['rules'] = entry[1].find('rules')
                log_entry['team_set'] = team_set
            
                return_entries.append(log_entry)
        else:
            #print 'no records'
            pass
        return return_entries, return_raw

    def showLog(self, cb_path, child, no_header=False):
        log_entries, dum = self.getLog(cb_path, child)
        prev_rules = 'first'
        for entry in log_entries:
                new_rules = entry['rules']
                if new_rules != prev_rules:
                    rules_str = 'no filter'
                    if new_rules is not None:
                        rules_str = new_rules.text
                    if not no_header:
                        print('%s %s %s' % (child, os.path.basename(cb_path), rules_str))
                    prev_rules = new_rules
                load_fail = ''
                if entry['load_fail'] is not None:
                    load_fail = 'failed cb load'
                poll_fail = ''
                if entry['poll_fail'] != 0:
                    poll_fail = 'poll_fail'
                protected_bytes_read = 0
                pal = entry['protected_access']
                for p in pal:
                    if len(p) > 0:
                        try:
                            a = json.loads(p)
                            protected_bytes_read += a['length']
                        except:
                            print('could not load json from %s' % p)
                print '%s \t\t%6.1f \t%6d \t%6d \t%s \t%s \t%s \t%s \t%.2f \t%d \t%s \t%s \t%s %s %s' % (entry['replay'], entry['duration'],
                        entry['cb_calls'], entry['replay_sys_calls'], self.formatMorK(entry['cb_cycles']),
                        self.formatMorK(entry['cb_user_cycles']), entry['cb_faults'], entry['replay_faults'],
                        entry['wall_time'], protected_bytes_read, entry['sys_config'], entry['drone'], entry['display_event'], load_fail, poll_fail)


    def showRawLog(self, cb_path, child):
        dum, log_entries = self.getLog(cb_path, child)
        print('%s  %s' % (cb_path, child))
        for entry in log_entries:
            print(entry)
    
    def hasServiceCFG(self):
        retval = False
        print('hasServiceCFG look for cfg at %s' % self.SERVICE_CFG_NODE)
        try:
            stat = self.zk.exists(self.SERVICE_CFG_NODE)
            if stat is not None:
                retval = True
                print('hasServiceCFG has node at %s' % self.SERVICE_CFG_NODE)
        except kazoo.exceptions.NoNodeError:
            print('hasServiceCFG missing OUR_NODE')
            pass
        return retval

    def hasReplayCFG(self):
        retval = False
        print('hasReplayCFG look for cfg at %s' % self.REPLAY_CFG_NODE)
        try:
            stat = self.zk.exists(self.REPLAY_CFG_NODE)
            if stat is not None:
                retval = True
                print('hasReplayCFG has node at %s' % self.REPLAY_CFG_NODE)
        except kazoo.exceptions.NoNodeError:
            print('hasReplayCFG missing OUR_NODE')
            pass
        return retval

    def updateServiceCFG(self, data):
        bs = data.encode('latin-1')
        done = False
        while not done:
            if not self.hasServiceCFG():
                try:
                    self.zk.create(self.SERVICE_CFG_NODE, bs, makepath=True)
                    print('updateServiceCfg create %s' % self.SERVICE_CFG_NODE)
                    done = True
                except kazoo.exceptions.NodeExistsError:
                    print('updateServiceCfg got beaten trying to create %s try again' % self.SERVICE_CFG_NODE)
            else:
                try:
                    self.zk.set(self.SERVICE_CFG_NODE, bs)
                    print('updateServiceCfg set %s' % self.SERVICE_CFG_NODE)
                    done = True
                except kazoo.exceptions.NoNodeError:
                    stat = self.zk.exists(self.SERVICE_CFG_NODE)
                    print('updateServiceCfg failed to set %s try again stat was %s' % (self.SERVICE_CFG_NODE, str(stat)))
            time.sleep(3)

    def updateReplayCFG(self, data):
        bs = data.encode('latin-1')
        done = False
        while not done:
            if not self.hasReplayCFG():
                try:
                    self.zk.create(self.REPLAY_CFG_NODE, bs, makepath=True)
                    print('updateReplayCFG create %s' % self.REPLAY_CFG_NODE)
                    done = True
                except kazoo.exceptions.NodeExistsError:
                    print('updateReplayCfg got beaten trying to create %s' % self.REPLAY_CFG_NODE)
            else:
                try:
                    self.zk.set(self.REPLAY_CFG_NODE, bs)
                    print('updateReplayCFG set %s' % self.REPLAY_CFG_NODE)
                    done = True
                except kazoo.exceptions.NoNodeError:
                    print('updateReplayCFG failed to set %s try again' % self.REPLAY_CFG_NODE)
            time.sleep(3)
         
    ''' delete the replay cfg file, which should trigger the target to send its 
        replay log to the host '''
    def deleteReplayCFG(self, all_monitors=False):
        if all_monitors:
            num_monitors = len(self.zk.get_children(self.MY_IP))
            print 'deleteReplayCFG for %d monitors ' % num_monitors
            for instance in range(0, num_monitors):
                target_name = self.myip+'_%d' % instance
                our_node = MONITORS_NODE + '/'+target_name
                cfg_node = our_node +'/replay_cfg'
                print 'cfg_node is '+cfg_node+' our node was '+our_node
                try:
                    self.zk.delete(cfg_node)
                except kazoo.exceptions.NoNodeError:
                    pass
        else:
            try:
                self.zk.delete(self.REPLAY_CFG_NODE)
            except kazoo.exceptions.NoNodeError:
                pass

    def dumpReplayCfg(self):
        try:
            value, stat = self.zk.get(self.REPLAY_CFG_NODE)
            print value
        except kazoo.exceptions.NoNodeError:
            print('no node at %s' % self.REPLAY_CFG_NODE)
        
    def dumpServiceCfg(self):
        try:
            value, stat = self.zk.get(self.SERVICE_CFG_NODE)
            print('value of node at %s, stat: %s' % (self.SERVICE_CFG_NODE, str(stat)))
            print value
        except kazoo.exceptions.NoNodeError:
            print('no node at %s' % self.SERVICE_CFG_NODE)

    def getClientDbgNode(self, my_id):
        path = DBG_CLIENTS+'/client'
        node_path = self.zk.create(path, my_id, ephemeral=True, sequence=True, makepath=True)
        return os.path.basename(node_path)

    def hasClientDbgNode(self, node_name, watcher=None):
        retval = False
        path = DBG_CLIENTS+'/'+node_name
        try:
            stat = self.zk.exists(path, watch=watcher)
            if stat is not None:
                retval = True
        except kazoo.exceptions.NoNodeError:
            pass
        return retval

    def isZkHost(self):
        try:
            zk_hosts = open(self.cfg.zk_host, 'rb').read()
        except:
            return False
        parts = zk_hosts.split(',')
        for entry in parts:
            host, port = entry.split(':')
            #print('compare %s to %s' % (host, my_ip))
            if host == self.my_ip:
                #print('my_ip is %s' % host)
                return True
        return False

    def clearAllStatusNodes(self):
        self.zk.delete(MONITORS_STATUS_NODE, recursive=True)

