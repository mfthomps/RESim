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
import xml.etree.ElementTree as ET
import szk
import sys
import kazoo
import logging
import configMgr
import utils
import socket
import xml.etree.ElementTree as ET
'''
    Manage a queue of replay requests from dbg clients
'''
DONE = 'done'
class dbgQueue():
    def __init__(self, zk, lgr):
        self.zk = zk
        self.lgr = lgr
        self.saw = []

    def addReplay(self, package):
        '''
        Add a replay package to the debug queue.  Return the entry path so the client can delete
        it when done.
        '''
        path = szk.DBG_QUEUE+'/dbg_'
        queue_entry = None
        bs = package.encode('latin-1')

        print('in addReplay')
        try:
            #Create sequence number as queue entry
            queue_entry = self.zk.zk.create(path, bs, ephemeral=False, sequence=True) 
            self.lgr.debug('dbgQueue created queue entry path %s\n package: %s' % (queue_entry, package))
            print('addReplay added queue %s' % queue_entry)
        except kazoo.exceptions.NoNodeError:
            self.lgr.error('dbgQueue could not create sequence node at %s' % path)
        return queue_entry

    def getReplay(self, watcher, only_client=None, auto_analysis=False):
        '''
        Get a replay from the debug queue
        Put targetName in the lock so monitor can get replay info to decide if it is to continue
        debugging.
        '''
        self.lgr.debug('dbgQueue getReplay, watch should be set, watcher is %s' % watcher)
        children = self.zk.zk.get_children(szk.DBG_QUEUE, watch=watcher)
        retval = None
        if len(children) > 0:
            children.sort()
            for child in children:
                if child not in self.saw:
                    self.saw.append(child)
                    path = szk.DBG_QUEUE+'/'+child
                    stat = self.zk.zk.exists(path+'/lock') 
                    if stat is None:
                        try:
                            value, stat = self.zk.zk.get(path)
                            client_id, client_node = utils.decodePackageClient(value)
                            if only_client is not None and client_id != only_client:
                                print('getReplay see entry for %s, but we only want %s' % (client_id, only_client))
                                continue
                            root = ET.fromstring(value)
                            auto_analysis = root.find('auto_analysis')
                            use_ephemeral = True
                            if auto_analysis is not None:
                                use_ephemeral = False
                            self.zk.zk.create(path+'/lock', self.zk.getTargetName(), ephemeral=use_ephemeral) 
                            if self.zk.hasClientDbgNode(client_node):
                                print('getReplay node %s will return %s' % (child, value))
                                return value
                            else:
                                if auto_analysis is None:
                                    print('getReplay found orphan entry, delete it')
                                    self.zk.zk.delete(path, recursive=True)
                                else:
                                    print('auto analysis, return package')
                                    return value
                        except kazoo.exceptions.NodeExistsError:
                            pass 
        return retval

    def findTargetLock(self, target_name):
        '''
        Search debug queue entries for first locked by the named target
        '''
        self.lgr.debug('dbgQueue findTargetLock for %s' % target_name)
        children = self.zk.zk.get_children(szk.DBG_QUEUE)
        retval = None
        if len(children) > 0:
            children.sort(reverse=True)
            for child in children:
                    path = szk.DBG_QUEUE+'/'+child
                    lock = path+'/lock'
                    stat = self.zk.zk.exists(lock)
                    if stat is not None:
                        try:
                            value, stat = self.zk.zk.get(lock)
                            print('findTargetLock locked by %s, looking for  %s' % (value, target_name))
                            if value == target_name:
                                try:
                                    value, stat = self.zk.zk.get(path)
                                    retval = value
                                    break
                                except kazoo.exceptions.NoNodeError:
                                    pass
                        except kazoo.exceptions.NoNodeError:
                            # may have been deleted
                            pass 
        return retval

         
    def listQueue(self):
        children = self.zk.zk.get_children(szk.DBG_QUEUE)
        for child in children:
            value, stat = self.zk.zk.get(szk.DBG_QUEUE+'/'+child)
            root = ET.fromstring(value)
            throw_id = root.find('throw_id')
            if throw_id is not None:
                print('%s %s' % (child, throw_id.text))
            else:
                print('no throw_id in %s' % child)
            other = self.zk.zk.get_children(szk.DBG_QUEUE+'/'+child)
            for o in other:
                lock_value, stat = self.zk.zk.get(szk.DBG_QUEUE+'/'+child+'/'+o)
                print('%s %s' % (o, lock_value))
         
    def cleanQueue(self):
        children = self.zk.zk.get_children(szk.DBG_QUEUE)
        for child in children:
            self.zk.zk.delete(szk.DBG_QUEUE+'/'+child, recursive=True)
