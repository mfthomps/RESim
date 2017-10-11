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
import StringIO
import ConfigParser
import kazoo
'''
Relatively static configuration values.  Also see master.cfg for 
very different configuration values.

Note the loadFromZookeeper method is called by szk.py when it is
initialized, and that will cause some values below to be over-written.
The cfg_overrides file (named below) is typically what is loaded into th zk node.
'''
sim_lib_path = '/mnt/simics/simics-4.8/simics-4.8.125/linux64/lib/python/simmod'
class configMgr():
    def __init__(self, os_types=None):
        self.logdir = '/mnt/cgc/logs'
        self.sql_logdir = '/mnt/cgc/sql_logs'
        #self.logdir = '/tmp' 
        self.python_dir = '/usr/bin/python'
        self.single_replays = True
        self.coroner_count = 1
        self.zk_host = 'zookeeper'
        self.zk_port = 2181
        self.zk_host_file = '/mnt/cgc/zk_hosts.txt'
        self.cb_dir = '/mnt/vmLib/cgcForensicsRepo/CB-share/v2/CBs'
        self.artifact_dir = '/mnt/vmLib/cgcArtifacts'
        self.db_name = "test1"
        self.cc_db_name = 'code_coverage'
        self.workspace_base = '/mnt/simics/simicsWorkspace'
        self.master_cfg = '/usr/share/cgc-monitor/master.cfg'
        self.master_debug_cfg = '/usr/share/cgc-monitor/master_dbg.cfg'
        self.master_analysis_cfg = '/usr/share/cgc-monitor/master_viz.cfg'
        self.master_msc_cfg = '/usr/share/cgc-monitor/master_msc.cfg'
        self.master_pov_cfg = '/usr/share/cgc-monitor/master_pov.cfg'
        self.pov_cfg = 'pov'
        self.system_map = None
        self.cfe_moved_dir = '/mnt/vmLib/bigstuff/cfe-games/cfe_moved'
        self.cfe_cfg_files_dir = '/mnt/vmLib/bigstuff/cfe-games/cgc-forensics'
        self.cfe_done_files_dir = '/mnt/vmLib/bigstuff/cfe-games/forensics-done'
        self.auto_analysis_dir = '/mnt/vmLib/bigstuff/auto_analysis'
        if os_types is not None:
            self.system_map = {}
            for cell_name in os_types:
                if os_types[cell_name] == 'linux':
                    self.system_map[cell_name] = '/mnt/vmLib/cgcForensicsRepo/maps_cfe/linux-kernel.map'
                elif os_types[cell_name] == 'freeBSD':
                    self.system_map[cell_name]= '/mnt/vmLib/cgcForensicsRepo/maps_cfe/bsd-kernel.map'
                elif os_types[cell_name] == 'freeBSD64':
                    self.system_map[cell_name]= '/mnt/vmLib/cgcForensicsRepo/maps_cfe/bsd64-kernel.map'
                elif os_types[cell_name] == 'linux64':
                    self.system_map[cell_name]= '/mnt/vmLib/cgcForensicsRepo/maps_cfe/linux64-kernel.map'
                else:
                    self.lgr.error('configMgr, no system map for %s' % os_types[cell_name]) 
        #if bsd:
        #    self.system_map= '/mnt/vmLib/cgcForensicsRepo/maps_cfe/bsd-kernel.map'
        #else:
        #    self.system_map= '/mnt/vmLib/cgcForensicsRepo/maps_cfe/linux-kernel.map'
        self.cgc_bytes= '/mnt/vmLib/cgcForensicsRepo/maps_cfe/cgc_bytes.offset'
        self.maps_dir= '/mnt/vmLib/cgcForensicsRepo/maps_cfe'
        self.pov_vs_patched = False
        #self.system_map= 'System.map-3.13.2cgc-1977-'
        # set aside for ida debugging, this instance and greater. 
        self.dbg_host='10.20.200.101'
        self.dbg_instance='999'

        # force these to be loaded by the local config overrides
        self.cgc_event = None
        self.cgc_event_db = None
        self.fix_headers = False
        self.artifact_server = None

        self.scoring_server = '10.10.10.30'
        self.cfg_overrides = '/etc/cgc-monitor/monitorCfgOverrides.cfg'
        self.replay_master_cfg = '/usr/share/cgc-monitor/replay_master.xml'
        self.service_master_cfg = '/usr/share/cgc-monitor/service_master.xml'
        self.os_params_dir = '/mnt/vmLib/cgcForensicsRepo/maps_cfe'
        self.cfe = True
        self.protected_start = 0x4347C000
        self.protected_length = 4096
        self.min_latency = 0.0008
        # number of cycles in a keep-alive period
        self.keep_alive_cycles = 2000000
        # number of keep_alive print periods (combo of cycles and walltime, after
        # which to forceQuitReplay   Zero means never
        self.keep_alive_kill_count = 20
        #self.min_latency = 0.001

        # force this to be over-ridden in the overide config file
        self.repo_master = None
        self.use_z_sim = True
        self.use_matic = False
        self.all_configs = False
        self.no_monitor = False

    def modConfigNode(self, zk, old, new):
        try:
            value, stat = zk.zk.get(szk.CONFIG_NODE)
        except kazoo.exceptions.NoNodeError:
            print('no configuration node, exiting')
            exit(1)
        new_value = value.replace(old, new)
        zk.zk.set(szk.CONFIG_NODE, new_value)
        self.loadFromZookeeper(zk.zk)

    def loadFromZookeeper(self, zk):
        '''
        Override default values listed above based on what is found in zookeeper node.
        NOTE: the delayUntilBooted script does not load zk, so don't override values
        needed by that.
        '''
        try:
            value, stat = zk.get(szk.CONFIG_NODE)
        except kazoo.exceptions.NoNodeError:
            print 'no config node, using default values'
            return
        config_values = StringIO.StringIO(value)
        config = ConfigParser.ConfigParser()
        config.readfp(config_values)
        self.logdir = self.quietGetString(config, 'logging', 'log_dir', self.logdir)
        self.python_dir = self.quietGetString(config, 'scripts', 'python_dir', self.python_dir)
        self.single_replays = self.isYes(config.get('replays', "single_replays"))
        self.coroner_count = int(config.get('death_watch', 'coroner_count'))

        self.cb_dir = self.quietGetString(config, 'repo', 'cb_dir', self.cb_dir)
        self.cgc_event = self.quietGetString(config, 'repo', 'cgc_event', self.cgc_event)
        self.cgc_event_db = self.quietGetString(config, 'repo', 'cgc_event_db', self.cgc_event_db)
        try:
            self.fix_headers = self.isYes(config.get('repo', "fix_headers"))
        except:
            pass
        try:
            self.use_z_sim = self.isYes(config.get('model', "use_z_sim"))
        except:
            pass
        try:
            self.pov_vs_patched = self.isYes(config.get('replays', "pov_vs_patched"))
        except:
            pass
        try:
           self.all_configs = self.isYes(config.get('replays', "all_configs"))
        except:
            pass
        try:
           self.no_monitor = self.isYes(config.get('monitor', "no_monitor"))
        except:
            pass
        self.repo_master = self.quietGetString(config, 'repo', 'repo_master', self.repo_master)
        self.artifact_dir = self.quietGetString(config, 'logging', 'artifact_dir', self.artifact_dir)
        self.db_name = self.quietGetString(config, 'logging', 'db_name', self.db_name)
        self.cc_db_name = self.quietGetString(config, 'logging', 'cc_db_name', self.cc_db_name)
        self.workspace_base = self.quietGetString(config, 'scripts', 'workspace_base', self.workspace_base)
        if self.system_map is not None:
            self.system_map = self.quietGetString(config, 'kernel', 'system_map', self.system_map)

        self.dbg_host = self.quietGetString(config, 'debugger', 'dbg_host', self.dbg_host)
        self.dbg_instance = self.quietGetString(config, 'debugger', 'dbg_instance', self.dbg_instance)
        self.artifact_server = self.quietGetString(config, 'logging', 'artifact_server', self.artifact_server)
        self.pov_cfg = self.quietGetString(config, 'replays', 'pov_cfg', self.pov_cfg)
        self.keep_alive_kill_count = self.quietGetInt(config, 'replays', 'keep_alive_kill_count', self.keep_alive_kill_count)

    def isYes(self, value):
        if value.lower() == 'yes' or value.lower() == 'true':
           return True
        else:
           return False

    def quietGetString(self, config, section, param, default):
        try:
            return config.get(section, param)
        except:
            return default
        
    def quietGetInt(self, config, section, param, default):
        try:
            return int(config.get(section, param))
        except:
            return default
