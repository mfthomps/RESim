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
import utils
import dbgQueue
import os
'''
Manage monitor interactions for ida-client based debugging
'''
class throwMgr():
    def __init__(self, szk, lgr):
        self.zk = szk
        self.lgr = lgr
        self.dbg_queue = dbgQueue.dbgQueue(szk, lgr)
    def listThrows(self):
        children = self.zk.zk.get_children(szk.THROW_NODE)
        for child in children:
            path = szk.THROW_NODE+'/'+child
            value, stat = self.zk.zk.get(path)
            if stat is not None:
                status = ""
                done_node = path+'/'+'done'
                lock_node = path+'/'+'lock'
                stat = self.zk.zk.exists(done_node)
                who = ''
                if stat is not None:
                    who, stat = self.zk.zk.get(lock_node)
                    status = 'Done by %s' % who
                else:
                    stat = self.zk.zk.exists(lock_node)
                    if stat is not None:
                        who, stat = self.zk.zk.get(lock_node)
                        status = 'Locked by %s' % who
                print('%s\n\t%s' % (value, status))
            
    def encodeThrow(self, kind, cb, pov, target_name, client_id): 
        return kind+';'+cb+';'+pov+';'+target_name+';'+client_id

    def decodeThrow(self, throw):
        items = throw.split(';')
        kind = items[0]
        cb = items[1]
        replay = items[2]
        target_name = items[3]
        client_id = items[4]
        return self.throwType(kind, cb, replay, target_name, client_id)

    class throwType():
        def __init__(self, kind, cb, replay, target_name, client_id): 
            self.kind = kind
            self.cb = cb
            self.replay = replay
            self.target_name = target_name
            self.client_id = client_id
 
    def addThrow(self, cb, pov, target_name, info, kind, watcher=None):
        ''' 
        Add an entry into the hierarchy to trigger an analysis session in Ida 
        First confirm the client that added the dbgQueue entry is still kicking
        target_name is the monitor that generated the throw.
        '''
        retval = False
        # look at dbgQueue to find an entry that was locked by the given target_name
        self.lgr.debug("addThrow cb: %s pov: %s" % (cb, pov))
        replay = self.dbg_queue.findTargetLock(target_name)
        if replay is not None:
            client_id, client_node = utils.decodePackageClient(replay)
            if client_id is not None:
                # see if client session running, and set watch to kill dbg session if client goes away
                if self.zk.hasClientDbgNode(client_node, watcher):
       
                    if pov is None:
                        pov = 'None'
                    value = self.encodeThrow(kind, cb, pov, target_name, client_id)
                    node = self.zk.zk.create(szk.THROW_NODE+'/'+szk.THROW, value, None, 
                               ephemeral=False, sequence=True, makepath=False) 
                    self.lgr.debug("addThrow node: %s throw: %s" % (node, value))
                    retval = True
                else:
                    print('addThrow, no client dbg node for %s at %s' % (client_id, client_node))
            else:
                print('addThrow could not find client info in replay %s' % replay)
        else:
            print('addThrow could not find dbgQueue entry from %s' % target_name) 
        return retval

    def cleanThrows(self):
        self.zk.zk.delete(szk.THROW_NODE, -1, recursive=True)
        self.zk.zk.ensure_path(szk.THROW_NODE)

    def isThrowLocked(self, entry):
        retval = False
        throw_node = self.getNodeName(szk.THROW_NODE, szk.THROW, entry)
        lock_node = throw_node+'/lock'
        stat = None
        try:
            stat = self.zk.zk.exists(lock_node, None)
        except kazoo.exceptions.NoNodeError:
            pass 
        if stat is not None:
            retval = True
        return retval

    def isThrowDone(self, entry):
        retval = False
        throw_node = self.getNodeName(szk.THROW_NODE, szk.THROW, entry)
        done_node = throw_node+'/done'
        stat = None
        try:
            stat = self.zk.zk.exists(done_node, None)
        except kazoo.exceptions.NoNodeError:
            pass 
        if stat is not None:
            retval = True
        return retval

    def getThrowLock(self, entry):
        retval = False
        throw_node = self.getNodeName(szk.THROW_NODE, szk.THROW, entry)
        print 'get lock for throw node %s' % throw_node
        done_node = throw_node+'/done'
        stat = self.zk.zk.exists(done_node, None)
        if stat is None:
            try:
                self.zk.zk.create(throw_node+'/lock', self.zk.target_name, None, False, False, False) 
                retval = True
            except kazoo.exceptions.NodeExistsError:
                pass
        return retval

    def getThrow(self, watcher, ignore_lock=False):
        '''
        Find the next waiting debugger environment node
        These nodes are created by a monitor when run with a debug configuration
        '''
        throws = self.zk.zk.get_children(szk.THROW_NODE, watcher)
        last_entry = -1
        done = False
        retval = None
        throw_node = None
        #print 'in getThrow'
        while not done:
            next_entry = self.findNextChild(throws, last_entry)
            #print 'got next entry of %d last entry was %d' % (next_entry, last_entry)
            if next_entry >= 0 and (ignore_lock or self.getThrowLock(next_entry)):
                throw_node = self.getNodeName(szk.THROW_NODE, szk.THROW, next_entry)
                try:
                    retval, stat = self.zk.zk.get(throw_node)
                    done = True
                except kazoo.exceptions.NoNodeError:
                    print('got lock but node gone, must have been a delete race')
            else:
                last_entry = next_entry
                #print 'failed lock last_entry now set to %d' % (last_entry)
                if last_entry is None or last_entry < 0:
                    print 'no throws found' 
                    break
            
        return retval, throw_node 
    def getThisThrow(self, watcher, cb, replay, client_id = None, ignore_lock=False):
        '''
        Find the waiting debugger environment node for a given replay
        '''
        print('getThisThrow for %s %s' % (cb, replay))
        throws = self.zk.zk.get_children(szk.THROW_NODE, watcher)
        last_entry = -1
        done = False
        retval = None
        throw_node = None
        #print 'in getThrow'
        while not done:
            next_entry = self.findNextChild(throws, last_entry)
            last_entry = next_entry
            if next_entry is None or next_entry < 0:
                print('no throws found')
                break
            if not self.isThrowDone(next_entry) and not self.isThrowLocked(next_entry):
                throw_node = self.getNodeName(szk.THROW_NODE, szk.THROW, next_entry)
                try:
                    value, stat = self.zk.zk.get(throw_node)
                except kazoo.exceptions.NoNodeError:
                    print('getThisThrow, node disappeared, must be delete race')
                    return
                    #TBD remove this exit
                    #exit(1)
                throw = self.decodeThrow(value) 
                if throw.cb.endswith('.rcb'):
                    common = throw.cb
                else:
                    common = utils.getCommonName(throw.cb)
                
                if replay.lower().endswith('.pov') and not throw.replay.lower().endswith('.pov'):
                    replay, dum = os.path.splitext(replay)
                if common == cb and throw.replay == replay and throw.client_id == client_id:
                    #print 'got next entry of %d last entry was %d' % (next_entry, last_entry)
                    if (ignore_lock or self.getThrowLock(next_entry)):
                        retval = value
                        done = True
                    else:
                        print('failed to get lock for what looked like our throw %s %s %s' % (cb, replay, client_id))
                else:
                    print('found throw for [%s] [%s] [%s], but we looked for [%s] [%s] [%s]' % (common, 
                         throw.replay, throw.client_id, cb , replay, client_id))
                    #TBD remove this exit
                    #exit(1)
            
        return retval, throw_node 

    def throwDone(self, throw_node):
        retval = False
        try:
            self.zk.zk.create(throw_node+'/done', self.zk.target_name, None, False, False, False) 
            retval = True
        except kazoo.exceptions.NodeExistsError:
            print 'could not mark throw node as done: %s' % throw_node
        return retval
    
    def getNodeName(self, path, prefix, entry):
        return '%s/%s%010d' % (path, prefix, entry)

    def numFromString(self, string, prefix):
        retval = None
        if not string.startswith(prefix):
            print 'cannot get sequence number from %s, prefix %s' % (string, prefix)
            exit(1)
        seq = string[len(prefix):]
        try:
            retval = int(seq)
        except:
            print 'cannot get sequence number from %s, prefix %s' % (string, prefix)
            exit(1)
        return retval
           
      
    def findNextChild(self, strings, last_target): 
        best = -1
        this = -1
        retval = None
        for child in strings:
            #print 'child is %s' % child
            this = self.numFromString(child, szk.THROW)
            if this == (last_target + 1):
                retval = this
                break
            else:
                if this > last_target:
                    if best < 0 or this < best:
                        best = this
        if retval is None:
            retval = best                
        return retval

