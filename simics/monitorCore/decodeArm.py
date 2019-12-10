from simics import *
import armCond
modsOp0 = ['ldr', 'mov', 'mvn', 'add', 'sub', 'mul', 'and', 'or', 'eor', 'bic', 'rsb', 'adc', 'sbc', 'rsc', 'mla']
reglist = ['pc', 'lr', 'sp', 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12']
def modifiesOp0(mn):
    for mop in modsOp0:
        if mn.startswith(mop):
            return True
    return False

def isReg(reg):
    if reg in reglist:
        return True
    else:
        return False 

def getMn(instruct):
    return instruct.split()[0]

def getOperands(instruct):
    mn, rest = instruct.split(' ',1)
    op1, op2 = rest.split(',', 1)
    return op2.strip(), op1.strip()

def isIndirect(reg):
    return False    

def regIsPart(op, reg):
    return op.lower() == reg.lower()

def isByteReg(reg):
    return False

def getRegValue(cpu, reg):
    try:
       reg_num = cpu.iface.int_register.get_number(reg)
    except:
       print('decodeArm getRegvalue failed reg <%s> cpu:%s' % (reg, str(cpu)))
       return None
    reg_value = cpu.iface.int_register.read(reg_num)
    return reg_value

def getValue(cpu, item, lgr=None):
    value = None
    if lgr is not None:
        lgr.debug('getValue for <%s>' % item)
    if isReg(item):
        value = getRegValue(cpu, item)
        if lgr is not None:
            lgr.debug('getValue IS A REG <%s>' % item)
    elif item.startswith('#'):
        lgr.debug('getValue NOT A REG <%s>' % item)
        if item.startswith('#0x'):
            try:
                value = int(item[3:], 16)
            except:
                return None
        else:
            try:
                value = int(item[1:])
            except:
                return None
    elif lgr is not None:
        lgr.debug('getValue failed to get value of <%s>' % item)
    return value 
        

def getAddressFromOperand(cpu, op, lgr):
    retval = None
    express = None
    if op[0] == '[' and op[-1] == ']':
        express = op[1:-1]
    elif op[0] == '[' and op[-2:-1] == ']!':
        express = op[1:-2]
    elif op[0] == '[' and '],' in op:
        rb = op.find(']')
        express = op[1:rb]
    if express is not None:
        value = 0
        parts = express.split(',')
        for p in parts:
            v = getValue(cpu, p.strip(), lgr=lgr) 
            if v is not None:
                value += v
            else:
                lgr.debug('getAddressFromOperand could not getValue from %s  op %s' % (p, op))
                return None    
        retval = value
    else:
        lgr.debug('getAddressFromOperand nothing from %s' % op)
    return retval
           
def armWriteBack(instruct, reg):
    mn, op0, op1 = instruct.split(' ', 2)
    if op1[0] == '[' and op1[-2:-1] == ']!':
        express = op1[1:-2]
        parts = express.split(',')
        if parts[0] == reg:
            return True 
    return False

def armSTR(cpu, instruct, addr, lgr):
    lgr.debug('armSTR')
    op1, op0 = getOperands(instruct)
    mn = getMn(instruct)
    retval = None
    if isReg(op0):
        retval = op0
    return retval

def armSTM(cpu, instruct, addr, lgr):
    lgr.debug('armSTM')
    op1, op0 = getOperands(instruct)
    mn = getMn(instruct)
    retval = None
    if op1.startswith('{') and op1.endswith('}'):
        regset = op1[1:-1]
        xregs = regset.split(',')
        regs = map(str.strip, xregs)
        if op0.endswith('!'):
            op0 = op0[:-1]
        mul = 1
        if 'd' in mn:
            mul = -1
        before = 0
        if 'b' in mn:
            before = 1
        reg_addr = getRegValue(cpu, op0)
        offset = (addr - reg_addr) * mul
        ''' TBD 64-bit '''
        count = (offset/4 - before)
        lgr.debug('armSTM addr 0x%x reg_addr 0x%x offset %d count %d mul %d before %d' % (addr, reg_addr, offset, count, mul, before))
        if count < 0 or count > len(regs)-1:
            lgr.error('count %d out of range with regs %s' % (count, str(regs)))
        if mul < 0:    
            regs.reverse() 
        retval = regs[count].strip()
    return retval

def armLDM(cpu, instruct, reg, lgr):
    op1, op0 = getOperands(instruct)
    mn = getMn(instruct)
    retval = None
    ''' incrementing or decrementing from addr in reg? '''
    mul = 1
    if len(mn) > 3 and 'd' in mn[3:]:
        mul = -1
    ''' adjusting before xfer or after '''
    before = 0
    if 'b' in mn:
        before = 1
    if op1.startswith('{') and op1.endswith('}'):
        regset = op1[1:-1]
        xregs = regset.split(',')
        regs = map(str.strip, xregs)
        if reg in regs:
            if mul < 0:
                regs.reverse()
            index = regs.index(reg) - before
            ''' TBD 64 bit?? '''
            offset = index * 4
            if op0.endswith('!'):
                op0 = op0[:-1]
            reg_addr = getRegValue(cpu, op0)
            retval = reg_addr + (offset * mul)
            lgr.debug('decodeArm armLDM reg %s, base %s base reg_addr value 0x%x index %d before %d mul %d returning 0x%x' % (reg, op0, reg_addr, index, before, mul, retval))
        else:
            lgr.debug('reg %s not in %s' % (reg, str(regs)))
    return retval

def isCall(cpu, instruct):
    N, Z, C, V = armCond.flags(cpu)
    if instruct.startswith('ble'):
        return Z or (N and not V) or (not N and V)
    if instruct.startswith('blt'):
        return (N and not V) or (not N and V)
    if instruct.startswith('blo'):
        return (not C)
    if instruct.startswith('bls'):
       return (not C) or Z
    elif instruct.startswith('bl'):
       return True
    return False
