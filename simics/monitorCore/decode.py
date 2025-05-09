'''
 * This software was created by United States Government employees
 * and may not be copyrighted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
'''
try:
    from simics import *
except:
    pass
modifiesOp0_list = ['mov', 'xor', 'pop', 'add', 'or', 'and', 'inc', 'dec', 'shl', 'shr', 'lea', 'xchg', 'imul', 'sub']
ia32_regs = ["eax", "ebx", "ecx", "edx", "ebp", "edi", "esi", "eip", "esp"]
ia64_regs = ["rax", "rbx", "rcx", "rdx", "rbp", "rdi", "rsi", "rip", "rsp", "eflags", "r8", "r9", "r10", "r11", 
                     "r12", "r13", "r14", "r15"]
def modifiesOp0(op):
    if op.startswith('movs'):
        return False
    elif op.startswith('mov') or op.startswith('cmov') or op in modifiesOp0_list:
        return True
    else: 
        return False

#2016-11-19 09:35:43,567 - DEBUG - cycleRegisterMod mn: mov op0: eax  op1: dword ptr [ebp+0x8]

def regIsPart(reg1, reg2, lgr=None):
    if reg1 is None or reg2 is None:
        return False
    if reg1 == reg2:
        return True
    if reg1.endswith('x') and reg1[1] == reg2[0]:
        return True
    if reg2.endswith('x') and reg2[1] == reg1[0]:
        return True
    if reg1.startswith('r') and reg2.startswith('r'):
        if reg1.startswith('r1'):
            if reg1[:3] == reg2[:3]:
                return True
        elif reg1[:2] == reg2[:2]:
                return True
        return False 
    if len(reg1) == 2 and len(reg2) == 2 and reg1[0] == reg2[0]:
        return True
    if len(reg1) == 3 and len(reg2) == 3 and reg1.endswith('x') and reg2.endswith('x') and reg1[1] == reg2[1]:
        return True
    # we hack a L or H suffix to xmm regs
    if reg1.startswith('xmm') and reg2.startswith(reg1):
        return True
    return False

def regLen(reg):
    if reg.startswith('r'):
        return 8
    elif reg.startswith('xmm'):
        return 16
    elif reg.startswith('e'):
        return 4
    elif len(reg) == 2 and reg.endswith('x'):
        return 2
    elif len(reg) == 2 and (reg.endswith('h') or reg.endswith('l')):
        return 1
    else:
        return 4

def regIsPartList(reg1, reg2_list):
    for reg2 in reg2_list:
        if regIsPart(reg1, reg2):
            return True
    return False

def isReg(reg):
    if reg is None:
        return False
    if reg in ia32_regs:
        return True
    if reg in ia64_regs:
        return True
    if reg.startswith('r') and (reg.endswith('b') or reg.endswith('w') or reg.endswith('d')):
        return True

    if reg.startswith('xmm') and not reg.startswith('xmmword'):
        return True

    if (len(reg) == 3 and reg.endswith('x')) or (len(reg) == 2 and reg[0] != '0'):
        try:
            dum = int(reg)
            return False
        except:
            pass
        return True
    else:
        return False

def isByteReg(reg):
    if len(reg) == 2 and not reg.endswith('x'):
        return True
    else:
       return False

def getTopComponentName(cpu):
     names = cpu.name.split('.')
     return names[0]

def getSigned(val):
    if(val & 0x80000000):
        val = -0x100000000 + val
    return val

def isConstant(s):
    is_integer = False
    try:
        value = int(s)
        is_integer = True
    except:
        pass 
        try:
            value = int(s, 16)
            is_integer = True
        except:
            pass
    return is_integer

def adjustRegInBrackets(s, lgr):
    retval = None
    if '[' in s:
        content = s.split('[', 1)[1].split(']')[0]
        if isReg(content):
            retval = content
        else:
            parts = content.split('+')
            if len(parts) == 1:
                parts = content.split('-')
            if len(parts) == 2:
                if isReg(parts[0]):
                    if isConstant(parts[1]):
                        retval = parts[0]
    return retval


def getInBrackets(cpu, s, lgr):
    cell_name = getTopComponentName(cpu)
    if s is not None and s.find('[') != -1 and s.find(']') != -1:
        #return s.split('[')[0], s.split('[', 1)[1].split(']')[0]
        prefix = None
        if s.count('[') == 2:
            new_s = s
            first = new_s[:s.find(']')+1]
            second = new_s[s.find(']')+1:] 
            #print 'cell_name: %s first is %s   second is %s' % (cell_name, first, second)
            dum, reg = getInBrackets(cpu, first, lgr)
            #print 'cell_name: %s got reg of %s' % (cell_name, reg)
            reg_num = cpu.iface.int_register.get_number(reg)
            if reg_num is not None:
                prefix = getSigned(cpu.iface.int_register.read(reg_num))
                #lgr.debug('cell_name: %s got prefix value of %d' % (cell_name, prefix))
            else:
                print('cell_name: %s could not get reg num for %s ' % (cell_name, reg))
                return None, None
            s = second
        content = s.split('[', 1)[1].split(']')[0]
        if prefix is None:
            prebracket = s.split('[')[0]
            #lgr.debug('cell_name: %s prebracket is %s' % (cell_name, prebracket))
            pieces = prebracket.split()
            if len(pieces) > 0:
                prefix = pieces[len(pieces)-1]
                if len(prefix.strip()) == 0:
                    prefix = None
                else:
                    #lgr.debug('cell_name: %s returning prefix of %s' % (cell_name, prefix))
                    pass
            
        return prefix, content

    else:
        return None, None

def getMn(instruct):
    parts = instruct.split()
    return parts[0].strip()

def getOperands(instruct):
    ret1 = None
    ret2 = None
    parts_comma = instruct.split(',')
    if len(parts_comma) == 1:
        ''' no comma '''
        parts = instruct.strip().split()
        if parts[0] == 'rep':
            if (parts[1].startswith('sto') and len(parts) > 2):
                ret1 = None
            else:
                ret1 = 'esi'
            ret2 = 'edi'
        elif len(parts) > 1:
            ''' TBD this is half-assed '''
            if parts[1] == 'dword' and parts[2] == 'ptr':
                ret1 = parts[3].strip()
            else:
                ret1 = parts[1].strip()
            
    else:
        ret2 = parts_comma[1].strip()
        if '[' in ret2 and 'ptr' in ret2:
            ret2 = '[' + ret2.split('[')[1]
        #parts = parts[0].split(' ')
        #ret1 = parts[len(parts) - 1]
        ret1 = parts_comma[0].split(' ',1)[1].strip()
    return ret2, ret1

def isIndirect(reg):
    indirect = {'esi', 'edi'}
    if reg in indirect:
        return True
    else:
        return False

def regMask(reg):
    nb = regLen(reg)
    if nb == 1:
        mask = 0xff
    elif nb == 2:
        mask = 0xffff
    elif nb == 4:
        mask = 0xffffffff
    else:
        mask = 0xffffffffffffffff
    return mask

def getValue(s, cpu, lgr=None, reg_values={}):
    retval = None
    #if lgr is not None:
    #    lgr.debug('getValue for %s' % s)
    s = s.strip()

    if '+' in s:
        parts = s.split('+',1)
        reg_size = 4
        if isReg(parts[0]):
            reg_mask = regMask(parts[0])
        else:
            reg_mask = 0xffffffffffffffff
 
        v1 = getValue(parts[0], cpu, lgr, reg_values=reg_values) 
        v2 = getValue(parts[1], cpu, lgr, reg_values=reg_values)
        if v1 is not None and v2 is not None:
            retval = (v1+v2) & reg_mask
            #if lgr is not None:
            #    lgr.debug('getValue for %s is + p1 0x%x p2 0x%x' % (s, v1, v2))
        elif lgr is not None:
            lgr.debug('decode getValue failed getting values from %s' % s)
    elif '-' in s:
        parts = s.split('-',1)
        p1val = getValue(parts[0], cpu, lgr, reg_values=reg_values) 
        p2val = getValue(parts[1], cpu, lgr, reg_values=reg_values)
        retval = p1val - p2val
        #if lgr is not None:
        #    lgr.debug('getValue for %s is - p1 0x%x p2 0x%x' % (s, p1val, p2val))
        
    elif '*' in s:
        retval = 1
        parts = s.split('*')
        for p in parts:
            got_value = getValue(p, cpu, lgr=lgr, reg_values=reg_values) 
            if got_value is not None:
                retval = retval * got_value
            else:
                if lgr is not None:
                    lgr.error('decode getValue failed to getvalue for part %s' % p)
                    break
    elif isReg(s):
        if s in reg_values:
            retval = reg_values[s]
        else:
            reg_num = cpu.iface.int_register.get_number(s)
            retval = cpu.iface.int_register.read(reg_num)
            #if lgr is not None:
            #    lgr.debug('getValue %s is reg, get its value 0x%x' % (s, retval))
    else:
        try:
            retval = int(s, 16)
        except:
            try: 
                retval = int(s)
                #if lgr is not None:
                #    lgr.debug('getValue returning 0x%x' % retval)
            except:
                if lgr is not None:
                    lgr.error('getValue could not parse <%s>' % s)
                pass
        #if lgr is not None and retval is not None:
        #    lgr.debug('getValue %s is scalar, get its value 0x%x' % (s, retval))
    return retval

        
def addressFromExpression(cpu, exp, lgr, reg_values={}):
    #TBD remove not used
    address = None
    if isReg(exp):
        keys = reg_values.keys()
        lgr.debug('decode addressFromExpression is %s in %s' % (exp, str(keys)))
        if exp in reg_values:
            address = reg_values[exp]
        else: 
            reg_num = cpu.iface.int_register.get_number(exp)
            address = cpu.iface.int_register.read(reg_num)
    else:
        parts = None
        if '+' in exp:
            parts = exp.split('+')
            address = 0
            for p in parts:
                address = address + getValue(p, cpu, lgr)
        elif '-' in exp: 
            ''' ever use? TBD '''
            parts = exp.split('-')
            address = getValue(parts[0], cpu, lgr) - getValue(parts[1], cpu, lgr)
        if parts is None:
            try:
                address = int(exp, 16)
            except:
                lgr.error('could not parse expression %s' % exp)
        
    return address


def getAddressFromOperand(cpu, operand, lgr, reg_values={}):
    prefix, bracketed = getInBrackets(cpu, operand, lgr)
    lgr.debug('bracketed it %s prefix is %s' % (bracketed, prefix))
    address = None
    if bracketed is not None:
        #address = addressFromExpression(cpu, bracketed, lgr, reg_values=reg_values)
        address = getValue(bracketed, cpu, lgr, reg_values=reg_values)
        if address is not None:
            #lgr.debug('bracketed value was %x' % address)
            offset = 0
            if prefix is not None:
               if prefix == 'fs:':
                   address = cpu.ia32_fs_base + address
                   #lgr.debug('prefix was fs, address now %x' % address)
               else:
                   try:
                      offset = int(prefix)
                      address = address + offset
                   except:
                      try:
                          offset = getSigned(int(prefix, 16))
                          #lgr.debug("adjusting by offset %d" % offset)
                          address = address + offset
                      except:
                          lgr.debug('did not parse offset %s' % prefix)
                          pass

        else:
            #lgr.debug('could not get reg number from %s' % bracketed)
            pass
    else:
        try:
            address = int(operand, 16)
        except:
            pass
        ''' TBDF Where did this come from?
        if isIndirect(operand):
            reg_num = cpu.iface.int_register.get_number(operand)
            if reg_num is not None:
                address = cpu.iface.int_register.read(reg_num)
                lgr.debug('indirect value was %x' % address)
            else:
                lgr.debug('could not get reg number from %s' % operand)
        '''
    return address


def getUnmapped(cpu, instruct, lgr):
    operands = getOperands(instruct)
    for operand in operands:
        #print 'operand is %s' % operand
        address = getAddressFromOperand(cpu, operand, lgr)
        if address is not None:
            phys_block = cpu.iface.processor_info.logical_to_physical(address, Sim_Access_Read)
            if phys_block.address == 0:
                #print 'found unmapped at %x' % address
                return address
            else:
                #lgr.debug('operand %s logical address: %x  phys not zero: %x' % (operand, address, phys_block.address))
                pass
    return None
           
   
def isCall(cpu, instruct, ignore_flags=False): 
    if instruct.startswith('call'):
       return True
    else:
       return False
   
def isBranch(cpu, instruct):
    if instruct.startswith('j'):
        return True
    else: 
        return False

def isJump(cpu, instruct, ignore_flags=False): 
    return isBranch(cpu, instruct)

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
        
def isLDRB(cpu, instruct):
    return False

def isRegInInstruct(reg, instruct):
    operands = getOperands(instruct)
    for operand in operands:
        if operand is not None and isReg(operand) and regIsPart(reg, operand):
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
