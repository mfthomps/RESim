import idautils
'''
Find LDR PC, ... instructions
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
        if instruct.lower().startswith('l') and 'pc' in instruct.lower():
            print('0x%x is l pc  %s' % (ins_addr, instruct))
