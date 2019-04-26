from simics import *
modsOp0 = ['ldr', 'mov', 'mvn', 'add', 'sub', 'mul', 'and', 'or', 'eor', 'bic', 'rsb', 'adc', 'sbc', 'rsc']
reglist = ['pc', 'lr', 'sp', 'r0', 'r1', 'r2', 'r3', 'r4', 'r6', 'r6',' r7', 'r8', 'r9', 'r10', 'r11', 'r12']
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
    return op == reg

def isByteReg(reg):
    return False

def getRegValue(cpu, reg):
    reg_num = cpu.iface.int_register.get_number(reg)
    reg_value = cpu.iface.int_register.read(reg_num)
    return reg_value

def getValue(cpu, item):
    value = None
    if isReg(item):
        value = getRegValue(cpu, value)
    elif item.startswith('#'):
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
    return None 
        

def getAddressFromOperand(cpu, op, lgr):
    retval = None
    if op[0] == '[' and op[-1] == ']':
        express = op[1:-1]
    elif op[0] == '[' and op[-2:-1] == ']!':
        express = op[1:-2]
    if express is not None:
        value = 0
        parts = express.split(',')
        for p in parts:
            v = getValue(cpu, p) 
            if v is not None:
                value += v
            else:
                self.lgr.debug('getAddressFromOperand could not getValue from %s  op %s' % (p, op))
                return None    
        retval = value
    else:
        self.lgr.debug('getAddressFromOperand nothing from %s' % op)
    return retval
           
def armWriteBack(instruct, reg):
    mn, op0, op1 = instruct.split(' ', 2)
    if op1[0] == '[' and op1[-2:-1] == ']!':
        express = op1[1:-2]
        parts = express.split(',')
        if parts[0] == reg:
            return True 
    return False

def armLDM(cpu, instruct, reg):
    op1, op0 = getOperands(instruct)
    mn = getMn(instruct)
    retval = None
    if op1.startswith('{') and op1.endswith('}'):
        regset = op1[1:-1]
        regs = regset.split(',')
        if reg in regset:
            index = regset.index(reg)
            ''' TBD 64 bit?? '''
            offset = index * 4
            if op0.endswith('!'):
                op0 = op0[:-1]
            retval = getRegValue(cpu, op0)
    return retval
