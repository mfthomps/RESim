'''
Return a list of load addresses and path names relative to an application root that correspond to a list of 
Windows paths extracted from a RESim showSOMap function.
'''
import os
import ntpath
import findProgram
class LoadAndPath():
    def __init__(self, load_addr, path):
        self.load_addr = load_addr
        self.path = path
def getStaticPaths(static_list, root_dir, lgr):
    retval = []
    with open(static_list) as fh:
        os.chdir(root_dir)
        for line in fh:
            line = line.strip()
            if line.lower().endswith('.dll') or line.lower().endswith('.exe'):
                addr = int(line.split()[1], 16)
                path = line.split()[2]
                base = ntpath.basename(path)    
                found_list = findProgram.getProg(base, quiet=True)
                found_path = None
                if len(found_list) == 0:
                    print('Nothing found for base %s' % base)
                elif len(found_list) == 1:
                    found_path = found_list[0]
                    item = LoadAndPath(addr, found_path)
                    retval.append(item)
                else:
                    for the_path in found_list:
                        if '\\' in path: 
                            path = path.replace('\\','/')
                        if path.lower().endswith(the_path.lower()):
                           found_path = the_path
                           item = LoadAndPath(addr, found_path)
                           retval.append(item)
    return retval
