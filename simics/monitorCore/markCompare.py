from simics import *
import decode
import decodeArm
class MarkCompare():
    def __init__(self, top, cpu, mem_utils, addr, trans_size, lgr):
        self.compare_instruction = None
        self.compare_eip = None
        self.compare_before_reference = False
        self.reference_not_compared = False
        self.top = top
        self.cpu = cpu
        self.addr = addr
        self.trans_size = trans_size
        self.mem_utils = mem_utils
        self.lgr = lgr
        if cpu.architecture == 'arm':
            self.decode = decodeArm
        else:
            self.decode = decode
        self.our_value = None 
        self.byte_match = False

        # NO INIT PAST HERE
        if self.addr is not None:
            self.findCompare()
 
    def noIterate(self):
        # temp hack to prevent iterations
        return self.byte_match

    def armLoadAfterCompare(self, eip):
        '''
        special case of arm pulling this trick, which seems to be in regx matchers:
             ...
             cmp r3, #0
             ldrb r1, [r0]  -- watch mark here
             bne  loc_1234
        '''
        retval = None
        if self.cpu.architecture == 'arm':
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            if instruct[1].startswith('ldr'):
                prev_eip = eip - instruct[0]
                prev_instruct = SIM_disassemble_address(self.cpu, prev_eip, 1, 0)
                if prev_instruct[1].startswith('cmp'):
                    next_eip = eip + instruct[0]
                    next_instruct = SIM_disassemble_address(self.cpu, next_eip, 1, 0)
                    if next_instruct[1].startswith('b'):
                        op2, retval = self.decode.getOperands(instruct[1])
                        self.lgr.debug('MarkCompare armLoadAfterCompare, found one eip 0x%x reg %s' % (eip, retval))
        return retval

    def armCompareOurRegNextLoad(self, eip, our_reg):
        ''' we know the instruction after eip is a branch.  if the instruction after that is a load followed by a compare with our reg,
            we have a regex type comparison with input data'''
        retval = False
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        next_eip = eip + 2*instruct[0]
        next_instruct = SIM_disassemble_address(self.cpu, next_eip, 1, 0)
        cmp_eip = next_eip + instruct[0]
        cmp_instruct = SIM_disassemble_address(self.cpu, cmp_eip, 1, 0)
        self.lgr.debug('MarkCompare armCompareOurRegNextLoad, next_eip 0x%x next_instruct %s should be cmp eip 0x%x %s' % (next_eip, next_instruct[1], cmp_eip, cmp_instruct[1]))
        if next_instruct[1].startswith('ldrb'):
            if cmp_instruct[1].startswith('cmp') and our_reg in cmp_instruct[1]:
                op2, op1 = self.decode.getOperands(next_instruct[1])
                cmp_addr = self.decode.getAddressFromOperand(self.cpu, op2, self.lgr)
                self.compare_eip = cmp_eip
                self.compare_instruction = cmp_instruct[1] 
                self.cmp_value = self.mem_utils.readByte(self.cpu, cmp_addr) 
                self.our_value = self.mem_utils.readByte(self.cpu, self.addr) 
                self.byte_match = True
                self.lgr.debug('MarkCompare armCompareOurRegNextLoad, op2: %s, addr 0x%x, value 0x%x our_value: 0x%x' % (op2, cmp_addr, self.cmp_value, self.our_value))
                retval = True
            else:
                self.lgr.debug('MarkCompare armCompareOurRegNextLoad, cmp_instruct not a compare to our reg, NOT HANDLED')
        else:
            self.lgr.debug('MarkCompare armCompareOurRegNextLoad, next_instruct not ldrb, NOT HANDLED')
        
    def findCompare(self):        
        eip = self.top.getEIP(self.cpu)
        our_reg = self.armLoadAfterCompare(eip)
        if our_reg is not None:
            if self.armCompareOurRegNextLoad(eip, our_reg):
                self.lgr.debug('markCompare findCompare got compare byte')
            else:
                self.compare_before_reference = True

        else:
            if True:
                our_reg = None 
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                if instruct[1].startswith('ldr') or instruct[1].startswith('mov'):
                    op2, our_reg = self.decode.getOperands(instruct[1])
                    self.lgr.debug('markCompare  findCompare got %s, our_reg %s' % (instruct[1], our_reg))
                eip = eip + instruct[0]
                relevent = False
                for i in range(9):
                    instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                    if instruct[1].startswith('cmp') or instruct[1].startswith('test'):
                        if our_reg is not None and our_reg in instruct[1]:
                            relevent = True
                        else:
                            self.lgr.debug('markCompare  findCompare got %s, BUT MISSING our reg %s' % (instruct[1], our_reg))
                        self.compare_instruction = instruct[1]
                        self.compare_eip = eip
                        if not relevent:
                            self.reference_not_compared = True
                        break
                    elif instruct[1].startswith('pop') and 'pc' in instruct[1]:
                        break
                    else:
                        if our_reg is not None and our_reg in instruct[1]:
                            relevent = True
                        eip = eip + instruct[0]

    def toString(self):
        retval = ''
        if self.byte_match:
            retval = 'byte match 0x%x compare our value: 0x%x to 0x%x' % (self.compare_eip, self.our_value, self.cmp_value)
        elif self.compare_before_reference:
            retval = 'CBR'
        elif self.reference_not_compared:
            retval = 'RNC'
        elif self.compare_instruction is not None:
            retval = '0x%x %s' % (self.compare_eip, self.compare_instruction)
        return retval
