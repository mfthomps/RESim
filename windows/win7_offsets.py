PROC_CREATE_INFO_OFFSET=0x58
PROG_NAME_OFFSET=0x18
# These are based on build 6.1
# offset within ETHREAD of thread id
THREAD_ID_OFFSET = 0x3c0
# offset within EPROCESS of thread head
THREAD_HEAD = 0x308
# offset of head within ETHREAD
THREAD_NEXT = 0x428
# offset within EPROCESS of count of active threads
ACTIVE_THREADS = 0x328
THREAD_STATE = 0x164
PEB_ADDR = 0x338
ts_pid = 384
ts_next = 952
ts_prev = 944
ts_comm = 0x2e0
# offset of user space page table base (cr3)
page_table = 0x28
proc_ptr = 0x210
