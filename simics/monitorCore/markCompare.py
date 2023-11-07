from simics import *
class MarkCompare():
    def armLoadAfterCompare(self, cpu, eip, lgr):
        '''
        special case of arm pulling this trick:
             ...
             cmp r3, #0
             ldrb r1, [r0]  -- watch mark here
             bne  loc_1234
        '''
        retval = False
        if cpu.architecture == 'arm':
            instruct = SIM_disassemble_address(cpu, eip, 1, 0)
            if instruct[1].startswith('ldr'):
                prev_eip = eip - instruct[0]
                prev_instruct = SIM_disassemble_address(cpu, prev_eip, 1, 0)
                if prev_instruct[1].startswith('cmp'):
                    next_eip = eip + instruct[0]
                    next_instruct = SIM_disassemble_address(cpu, next_eip, 1, 0)
                    if next_instruct[1].startswith('b'):
                        lgr.debug('MarkCompare armLoadAfterCompare, found one 0x%x' % eip)
                        retval = True
        return retval
                
    def __init__(self, top, cpu, lgr):
        self.compare_instruction = None
        self.compare_before_reference = False
        eip = top.getEIP(cpu)
        if self.armLoadAfterCompare(cpu, eip, lgr):
            self.compare_before_reference = True
        else:
            for i in range(10):
                instruct = SIM_disassemble_address(cpu, eip, 1, 0)
                if instruct[1].startswith('cmp') or instruct[1].startswith('test'):
                    self.compare_instruction = instruct[1]
                    break
                elif instruct[1].startswith('pop') and 'pc' in instruct[1]:
                    break
                else:
                    eip = eip + instruct[0]

    def toString(self):
        retval = ''
        if self.compare_before_reference:
            retval = 'CBR'
        elif self.compare_instruction is not None:
            retval = self.compare_instruction
        return retval
