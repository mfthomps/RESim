import idautils
'''
Find 
'''
def testBit(int_value, bit):
    mask = 1 << bit
    return(int_value & mask)

def bitRange(value, start, end):
    shifted = value >> start
    num_bits = (end - start) + 1
    mask = 2**num_bits - 1
    retval = shifted & mask
    return retval

def strToHex(s):
    full = ''.join('%02x' % ord(c) for c in s)
    retval = int(full, 16)
    return retval

for ea in idautils.Functions():
    for ins_addr in idautils.FuncItems(ea):
        instruct = idc.generate_disasm_line(ins_addr, 0)
        if instruct.lower().startswith('mov'):
            #print('0x%x is mov %s' % (ins_addr, instruct))
            parts = instruct.lower().split()
            if parts[1].startswith('r0') and parts[2].startswith('r'):
                next_instruct = idc.generate_disasm_line(ins_addr+4, 0)
                if next_instruct.lower().startswith('pop'):
                    print('0x%x is mov followed by pop %s' % (ins_addr, instruct))
