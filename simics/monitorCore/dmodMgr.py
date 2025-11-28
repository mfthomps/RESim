import os
import pickle
import shutil
import syscall
import dmod
import fdMgr
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
'''
    Manage dynamic modifiers, read replaces and such.
'''
class DmodMgr():
    def __init__(self, top, comp_dict, cell_name, run_from_snap, syscallManager, context_manager, mem_utils, task_utils, lgr):
        self.top = top
        self.comp_dict = comp_dict
        self.cell_name = cell_name
        self.run_from_snap = run_from_snap
        self.syscallManager = syscallManager
        self.context_manager = context_manager
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.lgr = lgr
        self.loaded_dmods = []
        self.removed_dmods = []
        self.fd_mgr = fdMgr.FDMgr(self.lgr)
        # for maintaining parallel file system, e.g. for /sys and /var/run
        self.path_prefix = None
        self.setupFileSystem()
        self.handleDmods()

    def handleDmods(self):
        '''
            We want to load all Dmods named in the ini file, unless they have been removed
            at any point.  In other words, once a dmod is removed, it cannot be restored in future
            snapshots (unless you change its name).
        '''
        self.lgr.debug('dmodMgr handleDmods cell %s' % self.cell_name)
        if 'DMOD' in self.comp_dict:
            already_loaded = []
            
            if self.run_from_snap is not None:

                dmod_file = os.path.join('./', self.run_from_snap, self.cell_name, 'dmod.pickle')
                if os.path.isfile(dmod_file):
                    dmod_dict = pickle.load( open(dmod_file, 'rb') )
                    # previously loaded, so do not load again (unless in snapshot)
                    self.removed_dmods = dmod_dict['removed_dmods']
                    self.lgr.debug('dmodMgr handleDmods loaded removed_dmods from pickle %s' % (str(self.removed_dmods)))
            self.top.is_monitor_running.setRunning(False)
            dlist = self.comp_dict['DMOD'].split(';')
            for dmod in dlist:
                dmod = dmod.strip()
                if len(dmod) == 0:
                    continue
                self.lgr.debug('dmodMgr target: %s now load any dmods from ini that were not removed, this dmod %s.' % (self.cell_name, dmod))
                if dmod not in self.removed_dmods:
                    self.loaded_dmods.append(dmod)
                    if self.runToDmod(dmod):
                        self.lgr.debug('dmodMgr Dmod %s pending for cell %s, need to run forward' % (dmod, self.cell_name))
                        print('Dmod %s pending for cell %s, need to run forward' % (dmod, self.cell_name))
                    else:
                        self.lgr.debug('dmodMgr Dmod is missing, cannot continue.')
                        print('Dmod is missing, cannot continue.')
                        self.top.quit()

            self.lgr.debug('dmodMgr cell %s done loading dmods from ini.  %d total loaded dmods (includes previous)' % (self.cell_name, len(self.loaded_dmods)))

        ''' Load readReplace items. '''
        if 'READ_REPLACE' in self.comp_dict:
            self.top.is_monitor_running.setRunning(False)
            dlist = self.comp_dict['READ_REPLACE'].split(';')
            for read_replace in dlist:
                read_replace = read_replace.strip()
                if self.top.readReplace(read_replace, cell_name=self.cell_name, snapshot=self.run_from_snap):
                    print('ReadReplace %s set for cell %s' % (read_replace, self.cell_name))
                else:
                    print('ReadReplace file %s is missing, cannot continue.' % read_replace)
                    self.top.quit()
       
    def pickleit(self, name): 
        self.lgr.debug('dmodMgr pickleIt')
        dmod_file = os.path.join('./', name, self.cell_name, 'dmod.pickle')
        #dmod_paths = self.syscallManager.getDmodPaths()
        dmod_pickle = {}
        #dmod_pickle['paths'] = dmod_paths 
        #dmod_pickle['loaded_dmods'] = self.loaded_dmods
        dmod_pickle['removed_dmods'] = self.removed_dmods
        self.lgr.debug('dmodMgr pickleIt cell %s saved %d removed dmods' % (self.cell_name, len(self.removed_dmods)))
        pickle.dump(dmod_pickle, open(dmod_file, "wb"))
        self.pickleFileSystem(name) 

    def rmDmod(self, path):
        self.lgr.debug('dmodMgr rmDmod cell %s path %s' % (self.cell_name, path))
        if path not in self.removed_dmods:
            self.removed_dmods.append(path)
    def rmAllDmods(self):
        self.lgr.debug('dmodMgr rmAllDmods cell %s' % (self.cell_name))
        for path in self.loaded_dmods:
            self.rmDmod(path)

    def runToSecondary(self, primary):
        self.lgr.debug('dmodMgr runToSecondary %s' % primary.path)
        self.runToDmod(primary.path, primary=primary)
 
    def runToDmod(self, dfile, run=False, background=False, comm=None, break_simulation=False, primary=None):
        retval = True
        if not os.path.isfile(dfile):
            print('No file found at %s' % dfile)
            return False
        mod = dmod.Dmod(self.top, dfile, self.mem_utils, self.cell_name, comm, self.run_from_snap, self.fd_mgr, self.path_prefix, self.lgr, primary=primary)
        operation = mod.getOperation()
        if primary is None:
            param_name = dfile
        else:
            secondary_count = primary.getSecondaryCount()
            param_name = dfile+'_secondary'+'_%d' % secondary_count
        call_params = syscall.CallParams(param_name, operation, mod, break_simulation=break_simulation)        
        self.lgr.debug('runToDmod %s file %s cellname %s operation: %s' % (mod.toString(), dfile, self.cell_name, operation))
        name = 'dmod-%s' % operation
        if operation == 'open':
           # TBD stat64 (and other stats) should be optional, since program logic may expect file to first be missing?
           # Use a syscall dmod if you want to
           if primary is None:
               op_set = ['open', 'openat']
           else:
               op_set = ['read','write','close','lseek','_llseek']
               if self.mem_utils.WORD_SIZE == 8:
                   op_set.remove('_llseek')
               name=name+'_secondary'
           self.lgr.debug('runToDmod file op_set now %s' % str(op_set))
        else:
           op_set = [operation]
        comm_running = False
        comms_not_running = []
        comm_list = mod.getComm()
        for mod_comm in comm_list:
            tids = self.task_utils.getTidsForComm(mod_comm)
            if len(tids) == 0:
                self.lgr.debug('runToDmod, %s has comm %s that is not runing.' % (mod.path, mod_comm))
                comms_not_running.append(mod_comm)
            else:
                self.lgr.debug('runToDmod, has comm that is runing, no callback needed.')
                comm_running = True
                break
        if comm_running or len(comm_list) == 0: 
            self.lgr.debug('runToDmod, at least one comm running (or no comm specified), call runTo')
            ignore_running = False
            if primary is not None:
                ignore_running = True
            self.top.runTo(op_set, call_params, cell_name=self.cell_name, run=run, background=background, name=name, all_contexts=True, ignore_running=ignore_running)
        else:
            self.lgr.debug('runToDmod, no comm is running, use comm callback for each comm')
            mod.setCommCallback(op_set, call_params)
            for mod_comm in comms_not_running:
                self.context_manager.callWhenFirstScheduled(mod_comm, mod.scheduled)
        return retval

    def setupFileSystem(self):
        self.path_prefix = './dmod_files'
        if not os.path.islink(self.path_prefix):
            if os.path.isdir(self.path_prefix):
                shutil.rmtree(self.path_prefix)
            if self.run_from_snap is not None:
                snap_path_prefix = '%s/%s/dmod_files' % (self.run_from_snap, self.cell_name)
                if os.path.isdir(snap_path_prefix):
                    #os.makedirs(self.path_prefix, exist_ok=True)
                    where = shutil.copytree(snap_path_prefix, './dmod_files')
                    self.lgr.debug('dmodMgr setupFileSystem copy tree went to %s' % where)

    def pickleFileSystem(self, snapname):
        if os.path.isdir(self.path_prefix):
            snap_path_prefix = '%s/%s/dmod_files' % (snapname, self.cell_name)
            where = shutil.copytree(self.path_prefix, snap_path_prefix)
            self.lgr.debug('dmodMgr pickleFileSystem copied %s to %s where:%s' % (self.path_prefix, snap_path_prefix, where))
        else:
            self.lgr.debug('dmodMgr pickleFileSystem no files at %s' % self.path_prefix)
         
