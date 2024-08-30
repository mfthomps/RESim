import resimUtils
import elfText
import os
import json
class ModuleInfo():
    def __init__(self, addr, size, name):
        self.addr = addr
        self.size = size
        self.name = name
class VxKModules():
    def __init__(self, top, cell_name, cpu, mem_utils, task_utils, targetFS, comp_dict, lgr):
        self.top = top
        self.cell_name = cell_name
        self.cpu = cpu
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.targetFS = targetFS
        self.lgr = lgr
        # TBD, this should be per task
        self.module_map = {}
        if 'MODULE' in comp_dict:
            module = comp_dict['MODULE']
            module_addr = int(comp_dict['MODULE_START'], 16)
            module_size = int(comp_dict['MODULE_SIZE'], 16)
            self.module_map[module] = ModuleInfo(module_addr, module_size, module)
            # tbd fix this
            self.task_utils.setProgName(module)
        if 'VXIMAGE_PATH' not in comp_dict:
            self.lgr.error('VXIMAGEPATH missing from ini file')
            return
       
        path = comp_dict['VXIMAGE_PATH']
        vx_bin = os.path.join(path, 'vxWorks')
        if not os.path.isfile(vx_bin):
            self.lgr.error('vxKModules file not found at %s' % vx_bin)
            return
        elf_info = elfText.getText(vx_bin, self.lgr)
        self.vx_start = elf_info.text_start
        self.vx_end = elf_info.text_start + elf_info.text_size - 1
        self.lgr.debug('vxKModules vx binary start: 0x%x end: 0x%x' % (self.vx_start, self.vx_end))
        path_base = os.path.basename(path)
        analysis_path = os.getenv('IDA_ANALYSIS')
        self.vx_fun_path = os.path.join(analysis_path, path_base, 'vxWorks'+'.fun')
            

    def getModuleInfo(self, name):
        if name in self.module_map:
            return self.module_map[name]
        else:
            return None

    def wordSize(self, tid):
        return 4 

    def isCode(self, addr, tid):
        retval = False
        prog, dumb = self.task_utils.getProgName(tid) 
        if prog in self.module_map:
            module_info = self.module_map[prog]
            if addr >= module_info.addr and addr < (module_info.addr + module_info.size):
                retval = True
            elif addr >= self.vx_start and addr <= self.vx_end:
                retval = True
        return retval
 

    def inModule(self, name=None, pc=None):
        if name is not None and name not in self.module_map:
            self.lgr.error('vxKModules inModule called with unknown name %s' % name)
            return False
        if pc is None:
            pc = self.top.getEIP(self.cpu)

        if pc >= self.vx_start and pc <= self.vx_end:
            #self.lgr.debug('vxKModules inModule pc 0x%x is in kernel' % pc)
            return False

        retval = False
        if name is None:
            name_list = list(self.module_map.keys())
        else:
            name_list = [name]
        for module in name_list:
            module_info = self.module_map[module]
            module_end = (module_info.addr + module_info.size)
            #self.lgr.debug('vxKModules inModule pc 0x%x between 0x%x and 0x%x?' % (pc, module_info.addr, module_end))
            if pc >= module_info.addr and pc < module_end:
                retval = True
                break
        return retval

    def getLocalPath(self, tid):
        return None

    def getProg(self, tid):
        # tbd manage by self
        prog_name, dumb = self.task_utils.getProgName(tid)
        return prog_name

    def getAnalysisPath(self, fname):
        root_prefix = self.top.getCompDict(self.cell_name, 'RESIM_ROOT_PREFIX')
        return resimUtils.getAnalysisPath(None, fname, root_prefix=root_prefix, lgr=self.lgr)
            
    def setFunMgr(self, fun_mgr, tid_in):
        if fun_mgr is None:
            self.lgr.warning('vxKModules setFunMgr input fun_mgr is none')
            return
        self.fun_mgr = fun_mgr
        fun_mgr.add(self.vx_fun_path, self.vx_start)

    def isMainText(self, pc):
        return True

    def isAboveLibc(self, pc):
        return True

    def getSOFile(self, pc):
        retval = None
        tid = self.task_utils.curTID()
        for prog in self.module_map:
            if self.inModule(prog, pc):
                retval = prog
                break
        if retval is None and self.isCode(pc, tid):
            retval = 'vxWorks'
        return retval

    def getSOInfo(self, pc):
        file = self.getSOFile(pc)
        start = None
        end = None
        if file is not None:
            if file in self.module_map:
                module_info = self.module_map[file]
                start = module_info.addr
                end = module_info.addr + module_info.size - 1
            elif file == 'vxWorks':
                start = self.vx_start
                end = self.vx_end
        return file, start, end

    def inVxWorks(self, pc):
        if pc >= self.vx_start and pc <= self.vx_end:
            return True
        else:
            return False

    def pickleit(self, name):
        return

    def moduleList(self):
        return list(self.module_map.keys())

    def getMachineSize(self, tid):
        return 4

    def getSO(self, quiet=False):
        retval = {}
        retval['tbd'] = 'TBD'
        ret_json = json.dumps(retval) 
        return ret_json

    def isLibc(self, pc):
        return False

