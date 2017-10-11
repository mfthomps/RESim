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
import socket
import configMgr
import szk
import logging
import accessSQL
import utils
import kazoo
import os
'''
Copy the master configuration files into the zk node
There are several varations of the configuarion file:
master -- what is used for vetting
debug -- used with Ida debugger
analysis -- generate traces
msc -- user created?
'''
class updateMasterCfg():
    def __init__(self, szk, cfg, lgr):
        self.szk = szk
        self.lgr = lgr
        self.cfg = cfg

    def recordMasterCfg(self, node):
        '''
        Record the master config and its checksum in the sql database
        '''
        sql = accessSQL.accessSQL(self.cfg.db_name, self.lgr)
        if sql is None:
            print('Missing mysql database %s' % self.cfg.db_name)
            exit(1)
        value = None
        if node == szk.MASTER_CONFIG_NODE:
            value, stat = self.szk.zk.get(szk.MASTER_CONFIG_NODE)
        elif node == szk.MASTER_DEBUG_CONFIG_NODE:
            value, stat = self.szk.zk.get(szk.MASTER_DEBUG_CONFIG_NODE)
        elif node == szk.MASTER_ANALYSIS_CONFIG_NODE:
            value, stat = self.szk.zk.get(szk.MASTER_ANALYSIS_CONFIG_NODE)
        elif node == szk.MASTER_MSC_CONFIG_NODE:
            value, stat = self.szk.zk.get(szk.MASTER_MSC_CONFIG_NODE)
        elif node == szk.MASTER_POV_CONFIG_NODE:
            value, stat = self.szk.zk.get(szk.MASTER_POV_CONFIG_NODE)
        checksum = utils.getChecksum(value)
        sql.addConfig(value, checksum)
        if sql is not None:
            sql.close()

    def getChecksum(self, node):
        '''
        get the master config checksum  for the given node
        '''
        value = None
        if node == szk.MASTER_CONFIG_NODE:
            value, stat = self.szk.zk.get(szk.MASTER_CONFIG_NODE)
        elif node == szk.MASTER_DEBUG_CONFIG_NODE:
            value, stat = self.szk.zk.get(szk.MASTER_DEBUG_CONFIG_NODE)
        elif node == szk.MASTER_ANALYSIS_CONFIG_NODE:
            value, stat = self.szk.zk.get(szk.MASTER_ANALYSIS_CONFIG_NODE)
        elif node == szk.MASTER_MSC_CONFIG_NODE:
            value, stat = self.szk.zk.get(szk.MASTER_MSC_CONFIG_NODE)
        elif node == szk.MASTER_POV_CONFIG_NODE:
            value, stat = self.szk.zk.get(szk.MASTER_POV_CONFIG_NODE)
        else:
            return None
        checksum = utils.getChecksum(value)
        return checksum

    def updateNamedMasterCfg(self, config_name):
        node, f = self.szk.nodeFromConfigName(config_name)
        retval = self.updateMasterCfg(node, open(f, 'rb').read())
        print('updateNamedMasterCfg for %s return cksum of %s' % (config_name, retval))
        return retval

    def updateAllMasterCfg(self, config=szk.MASTER_CONFIG_NODE):
        '''
        Update the three master config files using files named in the configMgr.
        Return the checksum of the given master.
        '''
        retval = None
        msc = None
        master = self.updateMasterCfg(szk.MASTER_CONFIG_NODE, open(self.cfg.master_cfg, 'rb').read())
        debug = self.updateMasterCfg(szk.MASTER_DEBUG_CONFIG_NODE, open(self.cfg.master_debug_cfg, 'rb').read())
        analysis = self.updateMasterCfg(szk.MASTER_ANALYSIS_CONFIG_NODE, open(self.cfg.master_analysis_cfg, 'rb').read())
        pov = self.updateMasterCfg(szk.MASTER_POV_CONFIG_NODE, open(self.cfg.master_pov_cfg, 'rb').read())
        if os.path.exists(self.cfg.master_msc_cfg):
            msc = self.updateMasterCfg(szk.MASTER_MSC_CONFIG_NODE, open(self.cfg.master_msc_cfg, 'rb').read())
        if config == szk.MASTER_CONFIG_NODE:
            retval = master
        elif config == szk.MASTER_DEBUG_CONFIG_NODE:
            retval = debug
        elif config == szk.MASTER_ANALYSIS_CONFIG_NODE:
            retval = analysis
        elif config == szk.MASTER_MSC_CONFIG_NODE:
            retval = msc
        elif config == szk.MASTER_POV_CONFIG_NODE:
            retval = pov
        return retval

    def updateMasterCfg(self, node, config):
        '''
        Write a given master configuration to the named master config node, creating it if needed
        This is intended for use by putMonitor and related tools to reflect the desired
        configuration via which the packages should be processed.
        '''
        try:
            self.szk.zk.create(node, config)
        except kazoo.exceptions.NodeExistsError:
            pass
        except kazoo.exceptions.NoNodeError:
            print 'updateMasterCfg error creating node at %s, missing node in path, exiting' % path
            raise kazoo.exceptions.NoNodeError
        self.szk.zk.set(node, config)

        self.recordMasterCfg(node)

        retval =  utils.getChecksum(config)
        print('in updateMasterCfg for node: %s,  checksum is %s' % (node, retval))
        return retval

    def findMasterCfg(self, find_checksum):
        value, stat = self.szk.zk.get(szk.MASTER_CONFIG_NODE)
        checksum = utils.getChecksum(value)
        if checksum == find_checksum:
            return value
        value, stat = self.szk.zk.get(szk.MASTER_DEBUG_CONFIG_NODE)
        checksum = utils.getChecksum(value)
        if checksum == find_checksum:
            return value
        value, stat = self.szk.zk.get(szk.MASTER_ANALYSIS_CONFIG_NODE)
        checksum = utils.getChecksum(value)
        if checksum == find_checksum:
            return value
        value, stat = self.szk.zk.get(szk.MASTER_POV_CONFIG_NODE)
        checksum = utils.getChecksum(value)
        if checksum == find_checksum:
            return value
        try:
            value, stat = self.szk.zk.get(szk.MASTER_MSC_CONFIG_NODE)
            checksum = utils.getChecksum(value)
            if checksum == find_checksum:
                return value
        except kazoo.exceptions.NoNodeError:
            print('no msc config node')
        return None
        

    def updateMasterCfgXX(self, cfg):
        '''
        Read the master config file and write it to the MASTER_CONFIG_NODE
        '''
        checksum = self.updateAllMasterCfg()
        self.lgr.debug('wrote all three configs, master config file %s to appropriate node, master checksum is %s' % (cfg.master_cfg, checksum))
        print('wrote all three configs, master config file %s to appropriate node, master checksum is %s' % (cfg.master_cfg, checksum))
        self.lgr.debug(open(cfg.master_cfg, 'rb').read())

if __name__ == "__main__":
    print('testing?')
