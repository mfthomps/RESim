import os
import json
class CommMap():
    def __init__(self, root_prefix, lgr):
        self.comm_map = {}
        self.lgr = lgr
        if root_prefix is not None:
             analysis_prefix = root_prefix.replace('images', 'analysis')
             comm_map_file = analysis_prefix+'.comm_map'
             if os.path.isfile(comm_map_file):
                 self.comm_map = json.load(open(comm_map_file))
                 self.lgr.debug('taskUtils loaded comm_map from %s' % comm_map_file)

    def commMatch(self, comm1, comm2):
        if comm1 == comm2:
            return True
        comm1_as = None
        comm2_as = None
        #self.lgr.debug('check %s against %s' % (comm1, comm2))
        if comm1 in self.comm_map: 
            #self.lgr.debug('comm1 %s in map as %s' % (comm1, self.comm_map[comm1]))
            if self.comm_map[comm1] == comm2:
                return True
            comm1_as = self.comm_map[comm1]
        if comm2 in self.comm_map:
            #self.lgr.debug('comm2 %s in map as %s' % (comm2, self.comm_map[comm2]))
            if self.comm_map[comm2] == comm1:
                return True
            comm2_as = self.comm_map[comm2]
        if comm1_as is not None and comm1_as == comm2_as:
            return True
        return False
