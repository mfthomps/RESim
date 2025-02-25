import os
def backstopCycles():
    backstop_cycles = 9000000
    backstop = os.getenv('BACK_STOP_CYCLES')
    if backstop is not None:
        backstop_cycles = int(backstop)
    return backstop_cycles
def hangCycles():
    hang_cycles = 90000000
    hang = os.getenv('HANG_CYCLES')
    if hang is not None:
        hang_cycles = int(hang)
    return hang_cycles
