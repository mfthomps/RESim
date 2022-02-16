import json
import os
import resimUtils
class FindTracks():
    ''' Find watch marks within given basic blocks '''
    def __init__(self, prog):
        self.prog_path = resimUtils.getProgPath(prog)
        self.track_data = {}
        self.track_bb = {}
        self.bb_cache = {}
        block_file = self.prog_path + '.blocks'
        if not os.path.isfile(block_file): 
            print('No block file at %s' % block_file)
            return
        with open(block_file) as fh:
            self.blocks = json.load(fh)

    def load(self, tfile):
        retval = True
        track_json = None
        if tfile not in self.track_data:
            with open(tfile) as fh:
                try:
                    track_json = json.load(fh)
                except:
                    #print('json load failed on %s' % tfile)
                    retval = False
            if track_json is not None:
                self.track_data[tfile] = track_json
                self.track_bb[tfile] = []
                for mark in self.track_data[tfile]:
                    bb = self.bbOfAddr(mark['ip']) 
                    self.track_bb[tfile].append(bb)
        return retval

    def bbOfAddr(self, addr):
        retval = None
        if addr in self.bb_cache:
            return self.bb_cache[addr]
        for fun in self.blocks:
            fun_i = int(fun)
            #print('check fun 0x%x against addr 0x%x' % (fun_i, addr))
            if fun_i < addr:
                continue
            for block_entry in self.blocks[fun]['blocks']:
                if addr >= block_entry['start_ea'] and addr <= block_entry['end_ea']:
                    #print('found BB 0x%x' % block_entry['start_ea'])
                    retval = block_entry['start_ea']
                    self.bb_cache[addr] = retval
                    break
        return retval

    def find(self, tfile, bb_in):
        ''' Is there a watch mark in the given basic block? '''
        retval = None
        if self.load(tfile):
            #print('searching %d marks' % len(self.track_data[tfile]))
            if bb_in in self.track_bb[tfile]:
                #print('found 0x%x' % bb_in)
                for mark in self.track_data[tfile]:
                    bb = self.bbOfAddr(mark['ip']) 
                    if bb == bb_in:
                        #print('found 0x%x' % bb)
                        retval = mark
                        break
        return retval
            
