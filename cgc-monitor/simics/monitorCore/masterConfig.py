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

import ConfigParser
import logging
import os
from monitorLibs import configMgr
from monitorLibs import accessSQL
import kazoo
import sys
import StringIO
#DEVEL = os.getenv('CGC_DEVEL')
#ZK_PY = '/mnt/cgc/zk/py'
#if DEVEL is not None and (DEVEL == 'YES'):
#    ZK_PY= '/mnt/cgcsvn/cgc/users/mft/zk/py'
#
#if ZK_PY not in sys.path:
#    sys.path.append(ZK_PY)
from monitorLibs import szk
from monitorLibs import utils
class masterConfig():
    '''
    access methods for data in the master.cfg file
    Also see the configMgr.py and master_replay.xml for other
    configuration files.  
    See the load method.  This data is generally read from 
    a zookeeper node
    '''
    checksum = None
    debug_cb = None
    trace_cb = None
    debug_pov = None
    stop_on_memory = None
    stop_on_signal = None
    stop_on_non_code = None
    stop_on_rop = None
    kernel_text = {}
    kernel_text_size = {}
    kernel_text2 = {}
    kernel_text_size2 = {}
    kernel_aslr = False
    stack_size = None
    ps_strings = None
    trace_target = None
    debug_process = None
    taint_process = None
    taint_bytes = None
    log_sys_calls =  False
    watch_replay = False
    watch_ids = False
    bail_on_failed_calls = 0
    reverse_size = 1200
    reverse_steps = 40000000000
    code_coverage = False
    track_protected_access = False
    auto_analysis = False
    def __init__(self, top, cell_config, zk):
        self.cell_config = cell_config
        self.top = top
        self.cfg = configMgr.configMgr()
        self.zk = zk

    def recordConfig(self):
        sql = accessSQL.accessSQL(self.cfg.db_name)
        value, stat = self.zk.zk.get(szk.MASTER_CONFIG_NODE)
        # obscure, don't use self.checksum, because that might be from an alternate config
        # this function records the master, regardless of what this monitor is using
        checksum = utils.getChecksum(value) 
        sql.addConfig(value, checksum)

    def isYes(self, value):
        if value is None:
            return False
        elif value.lower() == 'yes' or value.lower() == 'true':
           return True
        else:
           return False

    def stopOnSomething(self):
        return self.debug_cb | self.stop_on_memory | self.stop_on_signal | self.stop_on_non_code | self.stop_on_rop \
                             | (self.taint_process is not None) | (self.debug_process is not None)

    def watchNoX(self, cell_name, comm):
        if self.top.isCB(comm):
           return self.server_nox
        elif self.top.isPlayer(comm):
           return self.replay_nox
 
    def watchRop(self, cell_name, comm):
        if self.top.isCB(comm):
           return self.server_rop_cop
        elif self.top.isPlayer(comm):
           return self.replay_rop_cop

    def watchUID(self, cell_name, comm):
        if self.top.isCB(comm):
           return self.server_uid
        elif self.top.isPlayer(comm):
           return self.replay_uid
        elif self.top.isIDS(comm):
           return self.ids_uid

    def watchCalls(self, cell_name, comm):
        if self.top.isCB(comm):
           return self.server_calls
        elif self.top.isPoVcb(comm):
           return self.replay_calls
        #elif self.top.isReplay(comm):
        #   return self.watch_replay
        elif self.top.isIDS(comm):
           return self.ids_calls
        elif comm == self.trace_target:
           return True
        return False

    def kernelNoX(self, cell_name):
        if len(self.cell_config.os_type) == 1:
           return self.server_kernel_nox or self.replay_kernel_nox or self.ids_kernel_nox
        else: 
            kind = self.cell_config.cells[cell_name]
            if kind == 'network host':
                return self.server_kernel_nox
            elif kind == 'pov thrower':
               return self.replay_kernel_nox
            elif kind == 'ids':
               return self.ids_kernel_nox
            else:
               return False
 
    def kernelUnx(self, comm):
        if self.top.isCB(comm):
           return self.server_kernel_unx
        elif self.top.isPoVcb(comm):
           return self.replay_kernel_unx
        elif self.top.isIDS(comm):
           return self.ids_kernel_unx
        else:
           return False

    def kernelRop(self, comm):
        if self.top.isCB(comm):
           return self.server_kernel_rop
        elif self.top.isPoVcb(comm):
           return self.replay_kernel_rop
        elif self.top.isIDS(comm):
           return self.ids_kernel_rop
        else:
           return False

    def kernelPageTable(self, comm):
        if self.top.isCB(comm):
           return self.server_kernel_page_table
        elif self.top.isPoVcb(comm):
           return self.replay_kernel_page_table
        elif self.top.isIDS(comm):
           return self.ids_kernel_page_table
        else:
           return False

    def needPageFaults(self, cell):
        if self.stopOnSomething() or self.server_nox or self.replay_nox or \
           self.server_rop_cop or self.replay_rop_cop or self.code_coverage:
                return True
        else:
                return False
         
    def protectedMemory(self, cell_name, comm):
        retval = False
        if self.top.isCB(comm):
            if self.server_protected_memory:
                retval = True
        return retval

    def logLevel(self):
        if self.log_level == 'debug':
            return logging.DEBUG
        if self.log_level == 'info':
            return logging.INFO
        if self.log_level == 'critical':
            return logging.CRITICAL

    def watchIDS(self):
        if self.ids_kernel_rop or self.ids_kernel_unx or self.ids_calls:
            return True
        else:
            return False
        
    def watchPlayer(self):
        if self.replay_kernel_rop or self.replay_kernel_unx or self.replay_uid or self.replay_kernel_page_table \
           or self.replay_calls or self.replay_rop_cop or self.replay_nox:
            return True
        else:
            return False

    def watchReplay(self):
        return self.watch_replay

    def watchCbUser(self):
        if self.server_nox or self.server_rop_cop or self.server_protected_memory or self.code_coverage:
            return True
        else:
            return False

    def needSched(self):
        if self.server_kernel_rop or self.replay_kernel_rop or self.server_uid or self.replay_uid or self.replay_calls or self.server_calls or self.ids_calls:
            return True
        else:
            return False

    def logSysCalls(self):
        return self.log_sys_calls

    def watchSysCalls(self):
        return self.replay_calls or self.server_calls or (self.trace_target is not None)

    def validateConfig(self):
        if self.stopOnSomething() and not self.server_calls:
            print('cannot debug if not monitoring syscalls')
            return False
        return True

    def load(self, use_file=None, lgr=None):
        '''
        Load the master configuration from a file or a zk node.
        If an alternate configuraiton node exists, use that and delete it.
        '''
        print('masterConfig load, begin')
        lgr.debug('masterConfig load, begin')
        if use_file is not None:
            value = open(use_file, 'r').read()
        else:
            value = self.zk.getAlternateConfig()
            if value is not None:
                lgr.debug('found alt config node ') 
                print('alt cfg is %s' % value)
                lgr.debug('alt cfg is %s' % value)
                if self.zk.deleteAlternateConfig() != 0:
                    lgr.error('could not delete alt config node!')
                else: 
                    lgr.debug('alt config node deleted')
            else:
                print('no ALTERNATE_CONFIG_NODE, use master')
                lgr.debug('no ALTERNATE_CONFIG_NODE, use master')
                try:
                    value, stat = self.zk.zk.get(szk.MASTER_CONFIG_NODE)
                except kazoo.exceptions.NoNodeError:
                    print('no MASTER_CONFIG_NODE, cannot continue, exit')
                    lgr.debug('no MASTER_CONFIG_NODE, cannot continue, exit')
                    return False
        lgr.debug('masterConfig dump: %s' % value)
        config_values = StringIO.StringIO(value)
        config = ConfigParser.ConfigParser()
        try:
            config.readfp(config_values)
        except:
            print(' could not read config values from %s, fatal' % value)
            lgr.debug(' could not read config values from %s, fatal' % value)
            return False

        self.checksum = utils.getChecksum(value)
          
        print('masterConfig load, config checksum: %s' % self.checksum)
        lgr.debug('masterConfig load, config checksum: %s' % self.checksum)
        try:
            self.debug_cb = self.isYes(config.get("monitoring", "debug_cb"))
            self.trace_cb = self.isYes(config.get("monitoring", "trace_cb"))
            self.debug_pov = self.isYes(self.passGet(config, "monitoring", "debug_pov"))
            self.auto_analysis = self.isYes(self.passGet(config, "monitoring", "auto_analysis"))
            self.stop_on_memory = self.isYes(config.get("monitoring", "stop_on_memory"))
            self.stop_on_signal = self.isYes(config.get("monitoring", "stop_on_signal"))
            self.stop_on_non_code = self.isYes(config.get("monitoring", "stop_on_non_code"))
            self.stop_on_rop = self.isYes(config.get("monitoring", "stop_on_rop"))
            lsc = self.passGet(config, "monitoring", "log_sys_calls")
            if lsc is not None:
                self.log_sys_calls = self.isYes(lsc)
            try:
                self.bail_on_failed_calls = int(config.get("monitoring", "bail_on_failed_calls"))
            except:
                pass
            self.trace_target = None
            self.stack_size = int(config.get("kernel", "stack_size"), 16)
            self.ps_strings = int(config.get("kernel", "ps_strings"), 16)
            #self.cgc_text = int(config.get("kernel", "cgc_text"), 16)
            self.cgc_text_size = int(config.get("kernel", "cgc_text_size"), 16)
            self.server_name = config.get("network host", "name")
            self.ids_name = config.get("ids", "name")
            self.replay_name = config.get("pov thrower", "name")
            self.player_name = config.get("pov thrower", "player")
            self.server_nox = self.isYes(config.get("network host", "nox"))
            self.server_rop_cop = self.isYes(config.get("network host", "rop_cop"))
            self.replay_nox = self.isYes(config.get("pov thrower", "nox"))
            self.replay_rop_cop = self.isYes(config.get("pov thrower", "rop_cop"))
            self.server_uid = self.isYes(config.get("network host", "watch_uid"))
            self.replay_uid = self.isYes(config.get("pov thrower", "watch_uid"))
            self.ids_uid = self.isYes(config.get("ids", "watch_uid"))
            self.server_calls = self.isYes(config.get("network host", "sys_calls"))
            self.replay_calls = self.isYes(config.get("pov thrower", "sys_calls"))
            self.ids_calls = self.isYes(self.passGet(config, "ids", "sys_calls"))
            # example of param that may not exist, but still evals as false
            self.watch_replay = self.isYes(self.passGet(config, "pov thrower", "watch_replay"))
            self.code_coverage = self.isYes(self.passGet(config, "network host", "code_coverage"))
            self.log_level = config.get("logging", "level")
            self.server_kernel_rop = self.isYes(config.get("network host", "kernel_rop"))
            self.replay_kernel_rop = self.isYes(config.get("pov thrower", "kernel_rop"))
            self.ids_kernel_rop = self.isYes(config.get("ids", "kernel_rop"))
            self.server_kernel_nox = self.isYes(config.get("network host", "kernel_nox"))
            self.replay_kernel_nox = self.isYes(config.get("pov thrower", "kernel_nox"))
            self.ids_kernel_nox = self.isYes(config.get("ids", "kernel_nox"))
            self.server_kernel_unx = self.isYes(config.get("network host", "kernel_unx"))
            self.replay_kernel_unx = self.isYes(config.get("pov thrower", "kernel_unx"))
            self.ids_kernel_unx = self.isYes(config.get("ids", "kernel_unx"))
            self.server_kernel_page_table = self.isYes(config.get("network host", "kernel_page_table"))
            self.replay_kernel_page_table = self.isYes(config.get("pov thrower", "kernel_page_table"))
            self.ids_kernel_page_table = self.isYes(config.get("ids", "kernel_page_table"))
            self.rop_profile_record = self.isYes(config.get("rop profile", "record"))
            self.rop_profile_file = config.get("rop profile", "file")
            self.rop_profile_count = int(config.get("rop profile", "count"))
            self.server_protected_memory = self.isYes(config.get("network host", "protected_memory"))
            
            self.track_protected_access = self.isYes(self.passGet(config, "network host", "track_protected_access"))
         
            self.trace_target = self.passGet(config, "tracing", "target")
            self.debug_process = self.passGet(config, "monitoring", "debug_process")
            self.taint_process = self.passGet(config, "monitoring", "taint_process")
            self.taint_bytes = self.passGet(config, "monitoring", "taint_bytes")
            self.debug_cb = self.isYes(config.get("monitoring", "debug_cb"))
            aslr = self.passGet(config, "kernel", "aslr")
            if aslr is not None:
                self.kernel_aslr = self.isYes(aslr)

        except AttributeError:
            print('error reading values from config master.cfg')
            lgr.debug('error reading values from config master.cfg')
            return False
        #if not self.validateConfig():
        #    return False
        return True

    def getUnsigned64(self, val):
        return val & 0xFFFFFFFFFFFFFFFF

    def loadKSections(self, cell_name, lgr):
        ksections = 'ksections-%s.cfg' % self.cell_config.ip_address[cell_name]
        lgr.debug('loadKSections from %s' % ksections)
        kconfig = ConfigParser.ConfigParser()
        try:
            kconfig.read(ksections)
        except:
            print('masterConfig.py says no ksections.cfg file, tried to read %s' % ksections)
            lgr.debug('masterConfig.py says no ksections.cfg file, tried to read %s' % ksections)
            print os.listdir('./')
            return False
        self.kernel_text[cell_name] = int(kconfig.get("kernel", "text"), 16)
        self.kernel_text_size[cell_name] = int(kconfig.get("kernel", "text_size"), 16)
        lgr.debug('loadKsections text %x size %x' % (self.kernel_text[cell_name], self.kernel_text_size[cell_name]))
        self.kernel_text2[cell_name] = None
        self.kernel_text_size2[cell_name] = None
        
        self.kernel_text2[cell_name] = int(kconfig.get("kernel", "text2"), 16)
        if self.kernel_aslr:
            if self.cell_config.os_type[cell_name].endswith('64'):
                maxaddr = self.getUnsigned64(0xffffffffffffffff)
                val = maxaddr - self.kernel_text2[cell_name]
                lgr.debug('loadKsections %s maxaddr is 0x%x  and val is 0x%x start was 0x%x' % (cell_name, maxaddr, val, self.kernel_text2[cell_name]))
                self.kernel_text_size2[cell_name] = self.getUnsigned64(val)
            else:
                self.kernel_text_size2[cell_name] = 0xffffffff - self.kernel_text2[cell_name]
        else:
            self.kernel_text_size2[cell_name] = int(kconfig.get("kernel", "text2_size"), 16)
        lgr.debug('loadKsections text2 %x size %x' % (self.kernel_text2[cell_name], self.kernel_text_size2[cell_name]))

    def passGet(self, config, section, key):
        retval = None
        try:
            retval = config.get(section, key)
        except:
            pass
        return retval
