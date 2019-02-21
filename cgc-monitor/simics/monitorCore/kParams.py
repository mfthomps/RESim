class Kparams():
    def __init__(self):
        ''' assumptions '''
        #self.kernel_base = 3221225472
        self.kernel_base = 0xc0000000
        self.ram_base = 0
        self.stack_size = 8192
        self.ts_next_relative = True
        self.ts_state = None
        self.ts_active_mm = None
        self.ts_mm = None
        self.ts_binfmt = None
        self.ts_group_leader = None

        self.ts_next = None
        self.ts_prev = None
        self.ts_pid = None
        self.ts_tgid = None
        self.ts_comm = None
        self.ts_real_parent = None
        self.ts_parent = None
        self.ts_children_list_head = None
        self.ts_sibling_list_head = None
        self.ts_thread_group_list_head = None
        # vdr
        #self.current_task = 0xc2001454
        self.current_task = None
        self.current_task_fs = True
        # int80 goes here
        self.sys_entry = None
        # sysenter instruction vectors here
        self.sysenter = None
        self.sysexit = None
        self.iretd = None
        self.page_fault = None
        self.syscall_compute = None
        self.syscall_jump = None
        self.stack_frame_eip = None


    def printParams(self):
        print('Kernel parameters:')
        for k in self.__dict__.keys():
            v = self.__dict__.__getitem__(k)
            if v is not None:
                print('\t%-30s  %s' % (k, v))

    def getParamString(self):
        retval = 'Kernel parameters:\n'
        for k in self.__dict__.keys():
            v = self.__dict__.__getitem__(k)
            if v is not None:
                retval = retval + '\t%-30s  %s\n' % (k, v)
        return retval
