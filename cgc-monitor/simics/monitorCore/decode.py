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

from simics import *
modifiesOp0_list = ['mov', 'xor', 'pop', 'add', 'or', 'and', 'inc', 'dec', 'shl', 'shr', 'lea', 'xchg']
ia32_regs = ["eax", "ebx", "ecx", "edx", "ebp", "edi", "esi", "eip", "esp"]
def modifiesOp0(op):
    if op.startswith('mov') or op in modifiesOp0_list:
        return True
    else: 
        return False

#2016-11-19 09:35:43,567 - DEBUG - cycleRegisterMod mn: mov op0: eax  op1: dword ptr [ebp+0x8]

def regIsPart(reg1, reg2):
    if reg1 == reg2:
        return True
    if reg1.endswith('x') and reg1[1] == reg2[0]:
        return True
    if reg2.endswith('x') and reg2[1] == reg1[0]:
        return True
    if len(reg1) == 2 and len(reg2) == 2 and reg1[0] == reg2[0]:
        return True
    return False

def isReg(reg):
    if reg in ia32_regs:
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
                lgr.debug('cell_name: %s got prefix value of %d' % (cell_name, prefix))
            else:
                print 'cell_name: %s could not get reg num for %s ' % (cell_name, reg)
                return None, None
            s = second
        content = s.split('[', 1)[1].split(']')[0]
        if prefix is None:
            prebracket = s.split('[')[0]
            #print 'cell_name: %s prebracket is %s' % (cell_name, prebracket)
            pieces = prebracket.split(' ')
            if len(pieces) > 0:
                prefix = pieces[len(pieces)-1]
                if len(prefix.strip()) == 0:
                    prefix = None
                else:
                    lgr.debug('cell_name: %s returning prefix of %s' % (cell_name, prefix))
            
        return prefix, content

    else:
        return None, None

def getMn(instruct):
    parts = instruct.split(' ')
    return parts[0]

def getOperands(instruct):
    ret1 = None
    ret2 = None
    parts = instruct.split(',')
    if len(parts) is 1:
        ''' no comma '''
        parts = instruct.split(' ')
        if parts[0] == 'rep':
            if (parts[1].startswith('sto') and len(parts) > 2):
                ret1 = None
            else:
                ret1 = 'esi'
            ret2 = 'edi'
        elif len(parts) > 1:
            ret1 = parts[1]
    else:
        ret2 = parts[1]
        #parts = parts[0].split(' ')
        #ret1 = parts[len(parts) - 1]
        ret1 = parts[0].split(' ',1)[1]
    return ret2, ret1

def isIndirect(reg):
    indirect = {'esi', 'edi'}
    if reg in indirect:
        return True
    else:
        return False

def getValue(s, cpu, lgr):
    retval = None
    lgr.debug('getValue for %s' % s)
    if '+' in s:
        parts = s.split('+',1)
        retval = getValue(parts[0], cpu, lgr) + getValue(parts[1], cpu, lgr)
    elif '-' in s:
        parts = s.split('-',1)
        retval = getValue(parts[0], cpu, lgr) - getValue(parts[1], cpu, lgr)
        
    elif '*' in s:
        retval = 1
        parts = s.split('*')
        for p in parts:
            retval = retval * getValue(p, cpu, lgr) 
    elif isReg(s):
        reg_num = cpu.iface.int_register.get_number(s)
        lgr.debug('getValue %s is reg, get its value' % s)
        retval = cpu.iface.int_register.read(reg_num)
    else:
        try:
            retval = int(s, 16)
            lgr.debug('getValue returning 0x%x' % retval)
        except:
            try: 
                retval = int(s)
                lgr.debug('getValue returning 0x%x' % retval)
            except:
                lgr.error('getValue could not parse %s' % s)
                pass
    return retval

        
def addressFromExpression(cpu, exp, lgr):
    address = None
    if isReg(exp):
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


def getAddressFromOperand(cpu, operand, lgr):
    prefix, bracketed = getInBrackets(cpu, operand, lgr)
    lgr.debug('bracketed it %s prefix is %s' % (bracketed, prefix))
    address = None
    if bracketed is not None:
        address = addressFromExpression(cpu, bracketed, lgr)
        if address is not None:
            lgr.debug('bracketedd value was %x' % address)
            offset = 0
            if prefix is not None:
               try:
                  offset = int(prefix)
                  address = address + offset
               except:
                  try:
                      offset = getSigned(int(prefix, 16))
                      lgr.debug("adjusting by offset %d" % offset)
                      address = address + offset
                  except:
                      print 'did not parse offset %s' % prefix
                      pass

        else:
            print 'could not get reg number from %s' % bracketed
    else:
        if isIndirect(operand):
            reg_num = cpu.iface.int_register.get_number(operand)
            if reg_num is not None:
                address = cpu.iface.int_register.read(reg_num)
                lgr.debug('indirect value was %x' % address)
            else:
                print 'could not get reg number from %s' % operand
    return address

def getAddressFromOperandXX(cpu, operand, lgr):
    prefix, bracketed = getInBrackets(cpu, operand, lgr)
    lgr.debug('bracketedd it %s prefix is %s' % (bracketed, prefix))
    address = None
    if bracketed is not None:
        reg_num = cpu.iface.int_register.get_number(bracketed)
        if reg_num is not None:
            address = cpu.iface.int_register.read(reg_num)
            lgr.debug('bracketed value was %x' % address)
            offset = 0
            if prefix is not None:
               try:
                  offset = int(prefix)
                  address = address + offset
               except:
                  try:
                      offset = getSigned(int(prefix, 16))
                      lgr.debug("adjusting by offset %d" % offset)
                      address = address + offset
                  except:
                      print 'did not parse offset %s' % prefix
                      pass

        else:
            print 'could not get reg number from %s' % bracketed
    else:
        if isIndirect(operand):
            reg_num = cpu.iface.int_register.get_number(operand)
            if reg_num is not None:
                address = cpu.iface.int_register.read(reg_num)
                lgr.debug('indirect value was %x' % address)
            else:
                print 'could not get reg number from %s' % operand
    return address

def getUnmapped(cpu, instruct, lgr):
    operands = getOperands(instruct)
    for operand in operands:
        #print 'operand is %s' % operand
        address = getAddressFromOperand(cpu, operand, lgr)
        if address is not None:
            phys_block = cpu.iface.processor_info.logical_to_physical(address, Sim_Access_Read)
            if phys_block.address is 0:
                #print 'found unmapped at %x' % address
                return address
            else:
                lgr.debug('operand %s logical address: %x  phys not zero: %x' % (operand, address, phys_block.address))
                pass
    return None
           
    
     
