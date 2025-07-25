import re
import sys
modsOp0 = ['li', 'm', 'sub', 'add', 'and', 'l', 's', 'r']
reglist = ['pc', 'lr']
for i in range(0,32):
    reg = 'r%d' % i
    reglist.append(reg)

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
    retval = instruct.split()[0]
    if retval.startswith('ldr') and retval.endswith('b') and len(retval)>4:
        ''' at&t all over again'''
        retval = 'ldrb'+retval[3:-1]
    return retval

def getOperands(instruct):
    
    parts = instruct.split()
    mn = parts[0]
    if len(parts) > 1:
        rest = parts[1:]
        mn, rest = instruct.split(' ',1)
        if ',' in rest:
            op1, op2 = rest.split(',', 1)
            return op2.strip(), op1.strip()
        else:
            return None, rest.strip()
    else:
        return None, None

def getOperands3(instruct):
    op2, op1 = getOperands(instruct)
    if '[' in op2:
        parts = op2.split('[')
        op3 = '['+parts[-1]
        op2 = parts[0].strip()[:-1]
    elif ',' in op2:
        parts = op2.split(',')
        op2 = parts[0].strip()
        op3 = parts[1].strip()
    else:
        op2 = op2.strip()
        op3 = None
    return op3, op2, op1
       
    return op3, op2, op1


def isIndirect(reg):
    return False    

def regIsPart(op, reg, lgr=None):
    retval = False
    if op.lower() == reg.lower():
        if lgr is not None:
            lgr.debug('regisPart op matches %s' % op)
        retval = True
    else:
        reg_prefixes = ['r', 'x', 'w']
        op_reg_prefix = op[0]
        reg_reg_prefix = reg[0]
        if op_reg_prefix in reg_prefixes and reg_reg_prefix in reg_prefixes:
            op_num = op[1:]
            reg_num = reg[1:]
            if lgr is not None:
                lgr.debug('regisPart are reg prefixes op_num %s reg_num %s' % (op_num, reg_num))
            if op_num == reg_num:
                retval = True
    if not retval:
        if lgr is not None:
            lgr.debug('regisPart op %s does not match reg %s' % (op, reg))
    return retval
    #return op.lower() == reg.lower()

def regIsPartList(reg1, reg2_list):
    for reg2 in reg2_list:
        if regIsPart(reg1, reg2):
            return True
    return False

def isByteReg(reg):
    return False

def getRegValue(cpu, reg, lgr=None):
    reg_value = None
    reg_num = None
    if reg.startswith('w'):
        use_reg = 'x'+reg[1:]
    else:
        use_reg = reg
    try:
       reg_num = cpu.iface.int_register.get_number(use_reg)
    except:
       print('decodeArm getRegvalue failed reg <%s> cpu:%s' % (use_reg, str(cpu)))
       if lgr is not None:
           lgr.error('decodeArm getRegvalue failed reg <%s> cpu:%s' % (use_reg, str(cpu)))
    if reg_num is not None and reg_num >= 0:
        try:
            reg_value = cpu.iface.int_register.read(reg_num)
        except:
           print('decodeArm getRegvalue failed reg <%s>  reg_num 0x%x cpu:%s' % (reg, reg_num, str(cpu)))
           if lgr is not None:
               lgr.error('decodeArm getRegvalue failed reg <%s>  reg_num 0x%x cpu:%s' % (reg, reg_num, str(cpu)))
    else:
        print('decodeArm getRegValue failed to get reg num for reg %s' % use_reg)
        if lgr is not None:
            lgr.error('decodeArm getRegValue failed to get reg num for reg %s' % use_reg)
    if reg.startswith('w'):
        reg_value = reg_value & 0xffffffff
    return reg_value

def getValue(item, cpu, lgr=None):
    item = item.strip()
    value = None
    if lgr is not None:
        lgr.debug('getValue for <%s>' % item)
    if isReg(item):
        value = getRegValue(cpu, item, lgr=lgr)
        if lgr is not None:
            lgr.debug('getValue IS A REG <%s>' % item)
    elif item.startswith('#'):
        if lgr is not None:
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
    else:
        try:
            value = int(item, 16)
        except:
            try:
                value = int(item)
            except:
                if lgr is not None:
                    lgr.debug('getValue failed to get value of <%s>' % item)
    return value 
        

def getAddressFromOperand(cpu, op, lgr, after=False):
    retval = None
    express = None
    remain = None
    op = op.strip()
    lgr.debug('decodePPC32 getAddressFromOperand %s' % op)
    if op.endswith(')'):
        lgr.debug('decodePPC32 getAddressFromOperand ends with )')
        index = op.index('(')
        lgr.debug('decodePPC32 getAddressFromOperand index of ( is %d' % index)
        reg = op[index+1:-1]
        lgr.debug('decodePPC32 getAddressFromOperand reg %s' % reg)
        reg_value = getValue(reg, cpu)
        if index != 0:
            express = op[0:index]
            if '0x' in express:
                try:
                    value = int(express, 16)
                except:
                     lgr.error('decodePPC32 getAddressFromOperand expected hex int got %s' % op)
                     return None
            else:
                try:
                    value = int(express)
                except:
                     lgr.error('decodePPC32 getAddressFromOperand expected int got %s' % op)
                     return None
            if reg_value is not None:
                retval = reg_value + value
            else:
                 lgr.error('decodePPC32 getAddressFromOperand reg_value none?')
        else:
            retval = reg_value
            
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
        regs = list(regs)
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
        count = int((offset/4 - before))
        lgr.debug('armSTM addr 0x%x reg_addr 0x%x offset %d count %d mul %d before %d' % (addr, reg_addr, offset, count, mul, before))
        if count < 0 or count > len(regs)-1:
            lgr.error('count %d out of range with regs %s' % (count, str(regs)))
        if mul < 0:    
            regs.reverse() 
        retval = regs[count].strip()
    return retval

def armLDM(cpu, instruct, reg, lgr):
    ''' return the value of what would be loaded into the reg register, assuming it is part of an LDM instruction '''
    op1, op0 = getOperands(instruct)
    mn = getMn(instruct)
    retval = None
    ''' incrementing or decrementing from addr in reg? '''
    mul = 1
    if len(mn) > 3 and 'd' in mn[3:]:
        #lgr.debug('armLDM mul -1')
        mul = -1
    ''' adjusting before xfer or after '''
    before = 0
    if 'b' in mn:
        before = 1
        #lgr.debug('armLDM before is 1')
    if op1.startswith('{') and op1.endswith('}'):
        regset = op1[1:-1]
        xregs = regset.split(',')
        regs_map = map(str.strip, xregs)
        regs = list(regs_map)
        if reg in regs:
            if mul < 0:
                regs.reverse()
                before = before*-1
            index = regs.index(reg) - before
            ''' TBD 64 bit?? '''
            offset = index * 4
            #lgr.debug('armLDM index %d  offset %d' % (index, offset))
            if op0.endswith('!'):
                op0 = op0[:-1]
            reg_addr = getRegValue(cpu, op0)
            retval = reg_addr + (offset * mul)
            #lgr.debug('decodeArm armLDM reg %s, base %s base reg_addr value 0x%x index %d before %d mul %d returning 0x%x' % (reg, op0, reg_addr, index, before, mul, retval))
        else:
            lgr.debug('reg %s not in %s' % (reg, str(regs)))
    return retval

def isCall(cpu, instruct, ignore_flags=False):
    if instruct.startswith('bl') or instruct.startswith('bctrl'):
       return True
    else:
       return False

def isJump(cpu, instruct, ignore_flags=False):
    if instruct.startswith('bl'):
        return False
    if instruct.startswith('b'):
        return True
    return False

def inBracket(op):
    retval = None
    op = op.strip()
    if op.startswith('[') and op.endswith(']'):
        retval = op[1:-1]
    return retval

def isBranch(cpu, instruct):
    if instruct.startswith('b') or isCall(cpu, instruct) or instruct.startswith('tb') or instruct.startswith('cb'):
        return True
    else:
        return False

def isDirectMove(instruct):
    retval = False
    if getMn(instruct).startswith('mov'): 
        op2, op1 = getOperands(instruct)
        try:
            dumb = int(op2)
            retval = True
        except:
            try:
                dumb = int(op2, 16)
                retval = True
            except:
                pass
    return retval

def regCount(op):
    retval = None
    if op.startswith('{') and op.endswith('}'):
        regset = op[1:-1]
        xregs = regset.split(',')
        regs = map(str.strip, xregs)
        regs = list(regs)
        retval = len(regs)
    return retval 


def isAdd(cpu, instruct, lgr=None):
    retval = False
    mn = getMn(instruct)
    if mn.startswith('add'):
        retval = True
    else:
        retval = False
    return retval

def isRegInInstruct(reg, instruct):
    operands = getOperands(instruct)
    for operand in operands:
        if operand is not None and regIsPart(reg, operand):
            return True
    return False 

def isScalarAdd(reg, instruct):
    retval = None
    mn = getMn(instruct)
    op2, op1 = getOperands(instruct)
    if op1 == reg:
        if mn == 'add':
            try:
                retval = int(op2, 16)
            except:
                pass
        elif mn == 'sub':
            try:
                retval = int(op2, 16)
                retval = retval * -1
            except:
                pass
    return retval 

def regLen(reg):
    # TBD fix when introduce 64 bit arm 
    return 4

def isLDRB(cpu, instruct):
    return False
