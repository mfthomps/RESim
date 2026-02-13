class WinKParams():
    def __init__(self, os_type):
        self.param_version = 11
        if os_type == 'WIN7':
            kernel_base = 0xffff000000000000
            self.kernel_base = kernel_base & 0xFFFFFFFFFFFFFFFF
        elif os_type == 'WINXP':
            kernel_base = 0x80000000
            self.kernel_base = kernel_base & 0xFFFFFFFF
        self.current_task = None
        self.current_thread_offset = None
        self.proc_ptr = None
        self.ts_next = None
        self.ts_prev = None
        self.ts_pid = None
        self.ts_comm = None
        self.sysenter = None
        self.sysexit = None
        self.sys_entry = None
        self.iretd = None
        self.sysret64 = None
        self.syscall_compute = None
        self.syscall_jump = None
        self.page_fault = None
        self.arm_entry = None
        self.ptr2stack = None
        self.saved_cr3 = None
        self.page_table = None
        self.thread_id_offset = None
        self.thread_next = None
        self.thread_prev = None
        self.thread_offset_in_prec = None
        self.count_offset = None

    def printParams(self):
        print('Windows Kernel parameters:')
        for k in self.__dict__.keys():
            v = self.__dict__.__getitem__(k)
            if v is not None:
                print('\t%-30s  %s' % (k, v))
    def getParamString(self):
        retval = 'Windows Kernel parameters:\n'
        for k in self.__dict__.keys():
            v = self.__dict__.__getitem__(k)
            if v is not None:
                retval = retval + '\t%-30s  %s\n' % (k, v)
        return retval
