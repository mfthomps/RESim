'''
Find arm add sp, ... instructions
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

def rotateRight(val, r_bits):
    ror = lambda val, r_bits, max_bits: \
        ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
        (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))
    return ror(val, r_bits, 32)

ea = get_screen_ea()
print('ea is %x' % ea)
start = get_segm_start(ea)
end = get_segm_end(ea)
print('code at 0x%x - 0x%x' % (start, end))
for addr in range(start, end, 4):
    ins = idc.read_dbg_dword(addr)
    opcode = bitRange(ins, 21,24)
    if opcode == 4:
        rd = bitRange(ins, 12, 15)
        if rd == 13:
            imm = bitRange(ins, 0, 7)
            rotate = bitRange(ins, 8, 11)
            op2 = rotateRight(imm, rotate*2)
            rn = bitRange(ins, 16, 19)
            print('add 0x%x  (im 0x%x shift %d) to %d into sp at addr 0x%x' % (op2, imm, rotate, rn, addr))
    elif opcode == 5:
        rd = bitRange(ins, 12, 15)
        if rd == 13:
            print('got ADC a 0x%x' % addr)
            break
            
