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


def condMet(cpu, mn):
    N, Z, C, V = flags(cpu)
    if mn.endswith('fd') or mn.endswith('fa') or mn.endswith('ed') or mn.endswith('ea'):
        mn = mn[:-2]
    if mn.endswith('b'):
        ' $#!&^^! why divergent mnemonics?'
        mn = mn[:-1]
    if mn.endswith('eq'):
        return Z
    elif mn.endswith('ne'):
        return not Z
    elif mn.endswith('hs'):
        return C
    elif mn.endswith('cs'):
        return C
    elif mn.endswith('lo'):
        return not C
    elif mn.endswith('cc'):
        return not C
    elif mn.endswith('mi'):
        return N
    elif mn.endswith('pl'):
        return not N
    elif mn.endswith('vs'):
        return V
    elif mn.endswith('vc'):
        return not V
    elif mn.endswith('hi'):
        return C and not Z
    elif mn.endswith('ls'):
        return not C and Z
    elif mn.endswith('ge'):
        return (N == V)
    elif mn.endswith('lt'):
        return (N != V)
    elif mn.endswith('gt'):
        return not Z and (N == V)
    elif mn.endswith('le'):
        return Z or (N != V)
    else:
        return True 
        
