N = 31
Z = 30
C = 29
V = 28
def flagSet(cpu, flag):
    val = cpu.cpsr
    mask = 1 << flag
    if val & mask != 0:
        return True
    else:
        return False
    
def nSet(cpu):
    return flagSet(cpu, N)
def zSet(cpu):
    return flagSet(cpu, Z)
def cSet(cpu):
    return flagSet(cpu, C)
def vSet(cpu):
    return flagSet(cpu, V)
def flags(cpu):
    return nSet(cpu), zSet(cpu), cSet(cpu), vSet(cpu)
