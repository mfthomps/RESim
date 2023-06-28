ntstatus_map = {}

## PUT ALL THE NSTATUS values here
ntstatus_map["STATUS_SUCCESS"] = 0x00000000


def getStatusMap():
    retval = {}
    for status in ntstatus_map:
        retval[ntstatus_map[status]] = status
    return retval

