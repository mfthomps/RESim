class Kparams():
    def __init__(self, cpu, word_size, platform):
        self.param_version = 11
        ''' assumptions '''

        #if cpu.architecture == 'arm':
        if cpu.architecture == 'arm':
            if platform != 'arm5':
                self.ram_base = 268435456
            else:
                self.ram_base = 0
            self.thread_size = 8192
        if cpu.architecture == 'arm64':
            self.ram_base = 268435456
            self.thread_size = 8192
        else:
            self.ram_base = 0
        self.stack_size = 8192

        if word_size == 4:
            self.kernel_base = 0xc0000000
        else:
            #kernel_base = 0xffffffff80000000
            kernel_base = 0xffff800000000000
            self.kernel_base = kernel_base & 0xFFFFFFFFFFFFFFFF
            #self.cur_task_offset_into_gs = 0xc700
            #self.cur_task_offset_into_gs = 0xa748
            #self.cur_task_offset_into_gs = 0xa780
            #self.cur_task_offset_into_gs = 0xb780
            # TBD fix getKernelParams for x86-64
            # should be able to remove this now
            self.cur_task_offset_into_gs = 0xc280


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
        self.current_task = None
       
        self.current_task_fs = False
        self.current_task_gs = False
        if cpu.architecture.startswith('x86'): 
            if word_size == 4:
                self.current_task_fs = True
            else:
                self.current_task_gs = True
        # int80 goes here
        self.sys_entry = None
        # sysenter instruction vectors here
        self.sysenter = None
        self.sysexit = None
        self.iretd = None
        self.sysret64 = None
        #if word_size == 8:
        #    ''' run the findExits.py script to get this last holdout, reported as illegal memory mapping '''
        #    self.sysexit = 0xffffffff813e909a 
        #self.compat_32_entry = 0xffffffff813e8fc0
        self.compat_32_entry = None
        self.compat_32_int128 = None
        self.compat_32_compute = None
        self.compat_32_jump = None
        # arm entry/exit
        self.arm_entry = None
        self.arm64_entry = None
        self.arm_ret = None
        self.arm_ret2 = None
        self.ppc32_entry = None
        self.ppc32_ret = None
        self.page_fault = None
        self.data_abort = None
        self.syscall_compute = None
        self.syscall_jump = None
        self.syscall64_jump = None
        self.stack_frame_eip = None
        # arm call-specific svc 
        self.arm_svc = False
        # No process local task ptr at base of kernel stack. Only refer to offset in fs segment
        self.fs_base = None
        self.delta = None

        self.gs_base = None
        self.mm_struct = None
        self.mm_struct_offset = None

        # some linux don't use same registers for syscalls at sysenter as they do at the computed jump table
        self.x86_reg_swap = False

    def printParams(self):
        print('Kernel parameters:')
        for k in sorted(self.__dict__.keys()):
            v = self.__dict__.__getitem__(k)
            if v is not None:
                print('\t%-30s  %s' % (k, v))

    def getParamString(self):
        retval = 'Kernel parameters:\n'
        for k in sorted(self.__dict__.keys()):
            v = self.__dict__.__getitem__(k)
            if v is not None:
                retval = retval + '\t%-30s  %s\n' % (k, v)
        return retval

    def assignParams(self, values):
        # used to hack new parameters
        for k in values.__dict__.keys():
            v = values.__dict__.__getitem__(k)
            if v is not None:
                self.__dict__.__setitem__(k, v)


