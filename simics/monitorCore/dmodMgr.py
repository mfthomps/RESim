import os
import pickle
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
    def __init__(self, top, comp_dict, cell_name, run_from_snap, syscallManager, lgr):
        self.top = top
        self.comp_dict = comp_dict
        self.cell_name = cell_name
        self.run_from_snap = run_from_snap
        self.syscallManager = syscallManager
        self.lgr = lgr
        self.loaded_dmods = []
        self.removed_dmods = []
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
            legacy = False
            
            if self.run_from_snap is not None:

                dmod_file = os.path.join('./', self.run_from_snap, self.cell_name, 'dmod.pickle')
                if os.path.isfile(dmod_file):
                    dmod_dict = pickle.load( open(dmod_file, 'rb') )
                    # previously loaded, so do not load again (unless in snapshot)
                    if 'removed_dmods' in dmod_dict:
                        self.removed_dmods = dmod_dict['removed_dmods']
                        self.lgr.debug('dmodMgr handleDmods loaded removed_dmods from pickle %s' % (str(self.removed_dmods)))
                    else:
                        legacy = True
                        # TBD this is broken nonsense. remove it after old snapshots wither
                        self.loaded_dmods = dmod_dict['loaded_dmods']
                        self.lgr.debug('dmodMgr loading legacy pickle %s %d previously loaded dmods' % (dmod_file, len(self.loaded_dmods)))
                        for dmod_path in dmod_dict['paths']:
                            if dmod_path not in self.loaded_dmods:
                                self.loaded_dmods.append(dmod_path)
                else:
                    legacy = True
                    dmod_file = os.path.join('./', self.run_from_snap, 'dmod.pickle')
                    if os.path.isfile(dmod_file):
                        self.lgr.debug('dmodMgr loading double legacy pickle %s' % dmod_file)
                        dmod_dict = pickle.load( open(dmod_file, 'rb') )
                        if self.cell_name in dmod_dict:
                            for dmod_path in dmod_dict[self.cell_name]:
                                already_loaded.append(dmod_path)
                                if dmod_path not in self.loaded_dmods:
                                    self.loaded_dmods.append(dmod_path)
                        else:
                            self.lgr.error('dmodMgr failed to find pickle.  nothing at legacy %s' % dmod_file)
                            self.top.quit()
            self.top.is_monitor_running.setRunning(False)
            dlist = self.comp_dict['DMOD'].split(';')
            for dmod in dlist:
                dmod = dmod.strip()
                if len(dmod) == 0:
                    continue
                if legacy:
                    self.lgr.debug('dmodMgr legacy now load any dmods from ini that were not either in snapshot or previously loaded.  %d previous loads' % len(self.loaded_dmods))
                    if dmod not in already_loaded and dmod not in self.loaded_dmods:
                        if self.run_from_snap is not None:
                            self.lgr.debug('dmodMgr handleMods, got dmod not in snapshot: %s' % dmod)
                        self.loaded_dmods.append(dmod)
                        if self.top.runToDmod(dmod, cell_name=self.cell_name):
                            self.lgr.debug('dmodMgr Dmod %s pending for cell %s, need to run forward' % (dmod, self.cell_name))
                            print('Dmod %s pending for cell %s, need to run forward' % (dmod, self.cell_name))
                        else:
                            self.lgr.debug('dmodMgr Dmod is missing, cannot continue.')
                            print('Dmod is missing, cannot continue.')
                            self.top.quit()
                else:
                    self.lgr.debug('dmodMgr target: %s now load any dmods from ini that were not removed, this dmod %s.' % (self.cell_name, dmod))
                    if dmod not in self.removed_dmods:
                        self.loaded_dmods.append(dmod)
                        if self.top.runToDmod(dmod, cell_name=self.cell_name):
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
        if 'REG_SET' in self.comp_dict:
            self.top.is_monitor_running.setRunning(False)
            dlist = self.comp_dict['REG_SET'].split(';')
            for reg_set in dlist:
                reg_set = reg_set.strip()
                if self.top.regSet(reg_set, cell_name=self.cell_name, snapshot=self.run_from_snap):
                    print('RegSet %s set for cell %s' % (reg_set, self.cell_name))
                else:
                    print('RegSet file %s is missing, cannot continue.' % reg_set)
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

    def rmDmod(self, path):
        self.lgr.debug('dmodMgr rmDmod cell %s path %s' % (self.cell_name, path))
        if path not in self.removed_dmods:
            self.removed_dmods.append(path)
    def rmAllDmods(self):
        self.lgr.debug('dmodMgr rmAllDmods cell %s' % (self.cell_name))
        for path in self.loaded_dmods:
            self.rmDmod(path)
