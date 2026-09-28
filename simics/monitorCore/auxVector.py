'''
Get values from the Linux Aux Vector, starting with text entry point.
'''
AT_ENTRY = 9
class AuxVector():
    def __init__(self, cpu, mem_utils, lgr):
        self.mem_utils = mem_utils
        self.cpu = cpu
        self.lgr = lgr
        self.vector_values = {}
        self.id_list = [AT_ENTRY]
        self.readStruct()

    def readStruct(self):
        ''' walk past arg and envp to structure and load it '''
        word_size = self.mem_utils.wordSize(self.cpu)
        sp = self.mem_utils.getRegValue(self.cpu, 'sp')
        argc = self.mem_utils.readWord(self.cpu, sp)
        env_addr = (argc + 3) * word_size + sp
        env_ptr = 0xffffff
        self.lgr.debug('execToText dynamic, env_addr starts at 0x%x sp was 0x%x' % (env_addr, sp))
        for i in range(1000):
            env_ptr = self.mem_utils.readAppPtr(self.cpu, env_addr, size=word_size)
            if env_ptr == 0:
                break
            env_addr = env_addr + word_size
        if env_ptr != 0:
            self.lgr.error('execToText failed to find null after env secion')
            return
        self.lgr.debug('execToText out of env loop env_addr 0x%x' % env_addr)
        vect_addr = env_addr + word_size
        for i in range(100):
            id_type = self.mem_utils.readWord(self.cpu, vect_addr)
            if id_type in self.id_list:
                self.vector_values[id_type] = self.mem_utils.readWord(self.cpu, vect_addr+word_size)
                if len(self.vector_values) == len(self.id_list):
                    break
            vect_addr = vect_addr + 2*word_size
        self.lgr.debug('execToText out of aux vector loop len of vector values is %d' % len(self.vector_values))
        return

    def getValue(self, val_id):
        retval = None
        if val_id in self.vector_values:
            retval = self.vector_values[val_id]
        else:
            self.lgr.error('auxVector getValue id 0x%x not in vector values' % val_id)
        return retval
