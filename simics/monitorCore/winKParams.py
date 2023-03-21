class WinKParams():
    def __init__(self):
        kernel_base = 0xffff000000000000
        self.kernel_base = kernel_base & 0xFFFFFFFFFFFFFFFF
        self.current_task = None
        self.ts_next = None
        self.ts_prev = None
        self.ts_pid = None
        self.sysenter = None
        self.sysexit = None
        self.iretd = None
        self.sysret64 = None
