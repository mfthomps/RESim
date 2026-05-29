# Linux Futex Command and Flag Definitions
FUTEX_WAIT = 0
FUTEX_WAKE = 1
FUTEX_FD = 2
FUTEX_REQUEUE = 3
FUTEX_CMP_REQUEUE = 4
FUTEX_WAKE_OP = 5
FUTEX_LOCK_PI = 6
FUTEX_UNLOCK_PI = 7
FUTEX_TRYLOCK_PI = 8
FUTEX_WAIT_BITSET = 9
FUTEX_WAKE_BITSET = 10
FUTEX_WAIT_REQUEUE_PI = 11
FUTEX_CMP_REQUEUE_PI = 12

FUTEX_CMD_MASK = 0xF  # Lowest 4 bits hold the main command
FUTEX_PRIVATE_FLAG = 128  # Bit 7 (0x80)
FUTEX_CLOCK_REALTIME = 256  # Bit 8 (0x100)

_commands = {
    FUTEX_WAIT: "FUTEX_WAIT",
    FUTEX_WAKE: "FUTEX_WAKE",
    FUTEX_FD: "FUTEX_FD",
    FUTEX_REQUEUE: "FUTEX_REQUEUE",
    FUTEX_CMP_REQUEUE: "FUTEX_CMP_REQUEUE",
    FUTEX_WAKE_OP: "FUTEX_WAKE_OP",
    FUTEX_LOCK_PI: "FUTEX_LOCK_PI",
    FUTEX_UNLOCK_PI: "FUTEX_UNLOCK_PI",
    FUTEX_TRYLOCK_PI: "FUTEX_TRYLOCK_PI",
    FUTEX_WAIT_BITSET: "FUTEX_WAIT_BITSET",
    FUTEX_WAKE_BITSET: "FUTEX_WAKE_BITSET",
    FUTEX_WAIT_REQUEUE_PI: "FUTEX_WAIT_REQUEUE_PI",
    FUTEX_CMP_REQUEUE_PI: "FUTEX_CMP_REQUEUE_PI",
}

def decodeFutex(op):
    """Decodes a futex_op integer into a list of its base operation and flags."""
    flags = []
    
    # 1. Extract the base command (lowest 4 bits)
    cmd = op & FUTEX_CMD_MASK
    flags.append(_commands.get(cmd, f"UNKNOWN_OP({cmd})"))
    
    # 2. Check for modifier flags
    if op & FUTEX_PRIVATE_FLAG:
        flags.append("FUTEX_PRIVATE_FLAG")
    
    if op & FUTEX_CLOCK_REALTIME:
        flags.append("FUTEX_CLOCK_REALTIME")
   
    retval = ' '.join(flags)     
    return retval

