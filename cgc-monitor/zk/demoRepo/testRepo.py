#!/usr/bin/python
from monitorLibs import szk
from monitorLibs import utils
import sys
import os
import shutil
import glob
'''
Test jig for populating a CB/PoV file hierarchy.  
Intended to be called by scripts such as testSet1.py
'''

cbs_dir = None
mapfile = None
class testRepo():
    def __init__(self, top_file, new_map=False):
        #print 'in testRepo init, topfile is %s' % top_file
        os.umask(0000)
        self.top_file = top_file
        try:
            os.mkdir(top_file)
        except:
            pass
        self.cbs_dir = top_file
        try:
            os.mkdir(self.cbs_dir, mode=0777)
        except:
            pass
        mode = 'a'
        if new_map:
            mode = 'w'
        self.mapfile = open('map.txt', mode) 
        if mode == 'w':
            self.mapfile.write('# demo repo map of author names to common names\n')

    def copyBins(self, orig_cb, cb_name, cb_path, num_bins, patched): 
        binaries = glob.glob(orig_cb+'*')
        if patched:
            #binaries = list(filter(lambda x: (x.endswith('_patched') or x.endswith('_partial')), binaries))
            binaries = list(filter(lambda x: x.endswith('_patched'), binaries))
        else:
            binaries = list(filter(lambda x: not (x.endswith('_patched') or x.endswith('_partial')), binaries))
        #binaries = [f for f in os.listdir(orig_dir) if re.match(r
        binaries.sort()
        if len(binaries) != num_bins:
            print '%s: patched: %r found %d bins, thought there would be %d' % (patched, orig_cb, len(binaries), num_bins)
            print binaries
            exit(1)
        i = 1
        for b in binaries:
            suffix = '_%02x' % i
            shutil.copyfile(b, cb_path+'/'+cb_name+suffix)
            i += 1
    def quietMakeDir(self, path):
        try:
            os.makedirs(path, mode=0777)
        except:
            pass

    '''
        Copy a CB, its povs and polls from a sample directory to a simulated CB file hierarchy
        Existing files are deleted.
    '''
    def doCB(self, cb_name, orig_cb, polls, povs, idss, clean_dir=True):
        print 'in doCB for '+cb_name+' polls: %d' % len(polls)+' povs  %d' % len(povs) +' ids: %d' % len(idss)
        if not os.path.exists(os.path.dirname(orig_cb)):
            print 'testRepo doCB, could not find %s, exiting' % orig_cb
            exit(1)
        cb_dir = self.cbs_dir+'/'+cb_name
        if clean_dir:
            try:
                shutil.rmtree(cb_dir)
            except:
                pass
        self.quietMakeDir(cb_dir)
        #print 'did makedirs for '+cb_dir
        cb_auth = cb_dir +'/'+ szk.AUTHOR
        self.quietMakeDir(cb_auth)
        cb_povs = cb_auth + '/'+szk.POVs
        self.quietMakeDir(cb_povs)
        cb_ids = cb_auth + '/'+szk.IDSs
        self.quietMakeDir(cb_ids)
        cb_polls = cb_auth + '/'+szk.POLLs
        self.quietMakeDir(cb_polls)
        num_bins = utils.numBins(cb_name)
        orig_dir, orig_file = os.path.split(orig_cb) 
        #print 'orig_dir is '+orig_dir+' orig_cb is '+orig_cb+' num bins is %d' % num_bins
        #flist = os.listdir(orig_dir)
        #print flist
        # multiple binaries in CB
        done = False
        orig_dir, orig_file = os.path.split(orig_cb) 
        cb_path = cb_auth+'/'+cb_name
        cb_mg_path = cb_auth+'/'+cb_name+'_'+szk.MG
        self.quietMakeDir(cb_path)
        self.quietMakeDir(cb_mg_path)
        self.copyBins(orig_cb, cb_name, cb_path, num_bins, False)
        self.copyBins(orig_cb, cb_name+"_"+szk.MG, cb_mg_path, num_bins, True)
            
        self.mapfile.write('%s\t\t%s\n' % (os.path.basename(orig_cb), cb_name))
        for poll in polls:
            base = os.path.basename(poll)
            if base.endswith('.xml') and base.startswith('GEN_'):
                num_str = base.split('.')[0]
                num_str = num_str.rsplit('_',1)[1]
                try:
                    poll_num = int(num_str)
                except:
                    print('could not get a poll number from %s, cb is %s  num_str is %s ? exit' % (base, cb_name, num_str))
                    exit(1)
                a_poll_name = 'SP_'+cb_name+'_%06d' % poll_num
                #print 'poll is %s  cb_polls is %s  a_poll_name is %s' % (poll,  cb_polls, a_poll_name+'.xml')
                self.quietMakeDir(cb_polls+'/'+a_poll_name)
                shutil.copyfile(poll, cb_polls+'/'+a_poll_name+'/'+a_poll_name+'.xml')
                self.mapfile.write('%s\t\t%s\n' % (os.path.basename(poll), a_poll_name+'.xml'))
            else:
                print('could not handle poll name %s' % poll)
        k = 0
        for pov in povs:
            if pov.endswith('.pov'):
                a_pov_name = 'POV_'+cb_name+'_ATH'+'_%06d' % k
                self.quietMakeDir(cb_povs+'/'+a_pov_name)
                shutil.copyfile(pov, cb_povs+'/'+a_pov_name+'/'+a_pov_name+'.pov')
                self.mapfile.write('%s\t\t%s\n' % (os.path.basename(pov), a_pov_name))
                k = k +1
        k = 0
        for ids in idss:
            if ids.endswith('.rules'):
                a_ids_name = 'IDS_'+cb_name+'_ATH'+'_%06d' % k
                self.quietMakeDir(cb_ids+'/'+a_ids_name)
                shutil.copyfile(ids, cb_ids+'/'+a_ids_name+'.rules')
                self.mapfile.write('%s\t\t%s\n' % (os.path.basename(ids), a_ids_name))
                k = k +1

    def addRCB(self, cfg):
        '''
        *****NOT USED, SEE cfeFlow***********
        Add a the files named withint CFE configuration file to the forensics file repo
        '''
        rcb_list = cfg.getRCBs()
        for rcb in rcb_list: 
            if not os.path.exists(os.path.dirname(rcb)):
                print 'testRepo, addRCB could not find %s, exiting' % rcb
                exit(1)
        base = os.path.basename(rcb_list[0])
        num_bins = '%02d' % len(rcb_list)
        cb_name = base.split('-')[1]
        #common = 'CB'+base[:11]+num_bins
        common = 'CB'+cb_name+num_bins
        #suffix = base[11:12]
        team = cfg.getTeamId()
        competitor_name = '%03d' % team
        cb_dir = self.cbs_dir+'/'+common
        if not os.path.exists(os.path.dirname(cb_dir)):
            print 'could not find %s, exiting' % cb_dir
            exit(1)
        cb_compet = cb_dir +'/'+ szk.COMPETITOR
        try:
            os.makedirs(cb_compet, mode=0777)
        except:
            pass
        cb_this_competitor = cb_compet+'/'+competitor_name
        cb_cbs = cb_this_competitor + '/'+szk.CBs
        try:
            os.makedirs(cb_cbs, mode=0777)
        except:
            pass
        bin_path = cb_cbs
        try:
            os.makedirs(bin_path, mode=0777)
        except:
            print('addRCB rcb %s already exists' % bin_path)
        for rcb in rcb_list: 
            dest =  bin_path+'/'+os.path.basename(rcb)
            print('copy rcb %s to  %s' % (rcb, dest))
            shutil.copyfile(rcb, dest)

        pov = cfg.getPov()
        if pov is not None:
            cb_povs = cb_this_competitor + '/'+szk.POVs
            try:
                os.makedirs(cb_povs, mode=0777)
            except:
                print('addRCB pov path %s already exists' % cb_povs)
                pass
            dest =  os.path.join(cb_povs,os.path.basename(pov))
            print('copy pov %s to  %s' % (pov, dest))
            shutil.copyfile(pov, dest)
        rules = cfg.getIDS()
        if rules is not None:
            cb_ids = cb_this_competitor + '/'+szk.IDS
            try:
                os.makedirs(cb_ids, mode=0777)
            except:
                pass
            dest =  os.path.join(cb_ids, os.path.basename(rules))
            shutil.copyfile(rules, dest)
    
    
    def doCompetitor(self, competitor_name, common, orig_cb, pov):
        #print 'in doCompetitor for '+competitor_name+' common '+common+' orig_cb '+orig_cb
        if not os.path.exists(os.path.dirname(orig_cb)):
            print 'could not find %s, exiting' % orig_cb
            exit(1)
        cb_name = common+'_'+competitor_name+'_00001'
        cb_dir = self.cbs_dir+'/'+common
        if not os.path.exists(os.path.dirname(cb_dir)):
            print 'could not find %s, exiting' % cb_dir
            exit(1)
        cb_compet = cb_dir +'/'+ szk.COMPETITOR
        try:
            os.makedirs(cb_compet, mode=0777)
        except:
            pass
        cb_this_competitor = cb_compet+'/'+competitor_name
        try:
            shutil.rmtree(cb_this_competitor)
        except:
            pass
        cb_cbs = cb_this_competitor + '/'+szk.CBs
        os.makedirs(cb_cbs, mode=0777)
        bin_path = cb_cbs+'/'+cb_name
        os.makedirs(bin_path, mode=0777)
        cb_povs = cb_this_competitor + '/'+szk.POVs
        os.makedirs(cb_povs, mode=0777)
        num_bins = utils.numBins(common)
        orig_dir, orig_file = os.path.split(orig_cb) 
        #print 'orig_dir is '+orig_dir+' orig_cb is '+orig_cb+' num bins is %d' % num_bins
        #flist = os.listdir(orig_dir)
        #print flist
        # multiple binaries in CB
        done = False
        orig_dir, orig_file = os.path.split(orig_cb) 
        binaries = glob.glob(orig_cb+'*')
        binaries = list(filter(lambda x: not x.endswith('_patched'), binaries))
        #binaries = [f for f in os.listdir(orig_dir) if re.match(r
        binaries.sort()
        if len(binaries) != num_bins:
            print 'found %d bins, thought there would be %d' % (len(binaries), num_bins)
            print binaries
            exit(1)
        i = 1
        for b in binaries:
            suffix = '_%02x' % i
            shutil.copyfile(b, bin_path+'/'+cb_name+suffix)
            i += 1
        a_pov_name = None    
        if pov is not None:
            a_pov_name = 'POV_'+common+'_'+competitor_name+'_00001'
            os.makedirs(cb_povs+'/'+a_pov_name, mode=0777)
            print 'will copy from '+pov
            dest = cb_povs+'/'+a_pov_name+'/'+a_pov_name+'.xml'
            print 'to '+dest
            #shutil.copyfile(pov, cb_povs+'/'+a_pov_name+'/'+a_pov_name+'.xml')
            shutil.copyfile(pov, dest)
        return cb_name, a_pov_name
