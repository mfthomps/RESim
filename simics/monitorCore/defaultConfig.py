import os
def backstopCycles():
    backstop_cycles = 9000000
    backstop = os.getenv('BACK_STOP_CYCLES')
    if backstop is not None:
        backstop_cycles = int(backstop)
    return backstop_cycles

def aflBackstopCycles():
    backstop_cycles =   1000000
    wrong = os.getenv('AFL_BACKSTOP_CYCLES') 
    if wrong is not None:
        print('*******ERROR **********  Use AFL_BACK_STOP_CYCLES, not AFL_BACKSTOP_CYCLES')
        return None
    backstop = os.getenv('AFL_BACK_STOP_CYCLES') 
    if backstop is not None:
        backstop_cycles = int(backstop)
    return backstop_cycles

def hangCycles(afl=False):
    hang_cycles = 90000000
    hang = os.getenv('HANG_CYCLES')
    if hang is not None:
        hang_cycles = int(hang)
    else:
        # sane defaults
        if afl:
           bsc = aflBackstopCycles()
        else:
           bsc = backstopCycles()
        hang2 = int(bsc * 2)
        hang_cycles = max(hang_cycles, hang2)
    return hang_cycles

