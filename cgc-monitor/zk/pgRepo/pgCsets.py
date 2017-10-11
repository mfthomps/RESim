#!/usr/bin/python
import cutils
import sys
import os
import shutil
sys.path.append('../py')
from monitorLibs import szk
from monitorLibs import utils
'''
Create a forensics-local repo of CBs / PoVs / polls from given data.
NOTE: gets all polls (for use in code coverage)
'''
class pgCsets():
    def __init__(self, cb_top, scoring_top, cfg, lgr=None, max_polls=None):
         
        self.cbs_dir = cb_top
        self.scoring_top = scoring_top
        self.lgr = lgr
        if lgr is None:
            self.lgr = utils.getLogger('pgCsets', cfg.logdir)
        self.max_polls = max_polls 
        print('pgCsets')
        self.event = cfg.cgc_event
        if cb_top is None:
            self.cbs_dir = cfg.cb_dir
        os.umask(000)

    def doCB(self, cb_name, cbs, pcbs, polls, povs, event_path):
        print('doCB %s' % cb_name)
        self.lgr.debug('pgCsets, doCB in doCB for '+cb_name+' polls: %d' % len(polls)+' povs  %d' % len(povs))
        cb_dir = self.cbs_dir+'/'+cb_name
        try:
            shutil.rmtree(cb_dir)
        except:
            pass
        cutils.safeMkDir(cb_dir)
        cb_auth = cb_dir +'/'+ szk.AUTHOR
        cutils.safeMkDir(cb_auth)
        cb_povs = cb_auth + '/'+szk.POVs
        cutils.safeMkDir(cb_povs)
        cb_polls = cb_auth + '/'+szk.POLLs
        cutils.safeMkDir(cb_polls)
        num_bins = utils.numBins(cb_name)
        done = False
        cb_path = cb_auth+'/'+cb_name
        cb_mg_path = cb_auth+'/'+cb_name+'_'+szk.MG
        cutils.safeMkDir(cb_path)
        cutils.safeMkDir(cb_mg_path)
         
        for b in cbs:
            suffix = '_%02x' % b.cb_index
            bin_path = os.path.join(cb_path, cb_name+suffix)
            source = os.path.join(self.scoring_top, event_path, b.file_path)
            self.lgr.debug('pgCsets, doCB would copy from %s to %s' % (source, bin_path))
            if not os.path.exists(bin_path):
                shutil.copyfile(source, bin_path)
         
        for b in pcbs:
            suffix = '_MG_%02x' % b.cb_index
            bin_path = os.path.join(cb_mg_path, cb_name+suffix)
            source = os.path.join(self.scoring_top, event_path, b.file_path)
            self.lgr.debug('pgCsets, doCB would copy from %s to %s' % (source, bin_path))
            if not os.path.exists(bin_path):
                shutil.copyfile(source, bin_path)
        sorted_polls = []
        for poll in polls:
            key = poll.file_path
            sorted_polls.append((key, poll))
        sorted_polls.sort()
        k = 0
        for p in sorted_polls:
            poll = p[1]
            if self.max_polls is not None and k >= self.max_polls: 
                break
            a_poll_name = 'SP_'+cb_name+'_%06d' % k
            #print 'poll is %s  cb_polls is %s  a_poll_name is %s' % (poll,  cb_polls, a_poll_name+'.xml')
            poll_dir = os.path.join(cb_polls, a_poll_name)
            cutils.safeMkDir(poll_dir)
            poll_path = os.path.join(cb_polls, a_poll_name, a_poll_name+'.xml')
            source = os.path.join(self.scoring_top, event_path, poll.file_path)
            self.lgr.debug('pgCsets, doCB would copy from %s to %s' % (source, poll_path))
            if not os.path.exists(poll_path):
                shutil.copyfile(source, poll_path)
            k = k +1
        sorted_povs = []
        for pov in povs:
            key = pov.file_path
            sorted_povs.append((key, pov))
        sorted_povs.sort()
        k = 0
        for p in sorted_povs:
            pov = p[1]
            a_pov_name = 'POV_'+cb_name+'_ATH'+'_%06d' % k
            pov_dir = os.path.join(cb_povs, a_pov_name)
            cutils.safeMkDir(pov_dir)
            pov_path =os.path.join(cb_povs, a_pov_name, a_pov_name+'.xml')
            source = os.path.join(self.scoring_top, event_path, pov.file_path)
            self.lgr.debug('pgCsets, doCB would copy from %s to %s' % (source, pov_path))
            if not os.path.exists(pov_path):
                shutil.copyfile(source, pov_path)
                f = open(pov_path, 'r')
                pov_text = f.read()
                f.close()
                bad = '/usr/share/cgc-replay'
                if bad in pov_text: 
                    replaced = pov_text.replace('/usr/share/cgc-replay', '/usr/share/cgc-docs', 1)
                    self.lgr.debug('replaced bad dtd path ****************************')
                    f = open(pov_path, 'w')
                    f.write(replaced)
                    f.close()
            k = k +1


        
if __name__ == "__main__":
    print('testing?')
