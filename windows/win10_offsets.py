PROC_CREATE_INFO_OFFSET=None
PROG_NAME_OFFSET=None
# These are based on prior to 19041
# offset within ETHREAD of thread id
THREAD_ID_OFFSET = 0x4e8
# offset within EPROCESS of thread head
# could be 0x470; 0x488; 0x498 or 0x5e0
THREAD_HEAD = 0x488
# offset of head within ETHREAD
THREAD_NEXT = 0x4e0
# offset within EPROCESS of count of active threads
ACTIVE_THREADS = 0x5f8
THREAD_STATE = None
PEB_ADDR = 0x550
#
ts_pid = 0x2E0 
#ts_pid = 0x440 after 19041
ts_next = 0x2e8 
#ts_next = 0x448 after 19041
#ts_prev always right after ts_next
ts_prev = 0x2f8
ts_comm = 0x450 
#ts_comm = 0x5a8 after 19H1
# offset of user space page table base (cr3)
page_table = 0x28
# TBD meltdown page table directories
proc_ptr = 0x220
