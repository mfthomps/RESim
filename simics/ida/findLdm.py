'''
Find arm ldm of r0, r1, r2 and pc 
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

ea = get_screen_ea()
print('ea is %x' % ea)
start = get_segm_start(ea)
end = get_segm_end(ea)
print('code at 0x%x - 0x%x' % (start, end))
for addr in range(start, end, 4):
    ins = idc.read_dbg_dword(addr)
    if ins is None:
        print('addr 0x%x reads none')
    opcode = bitRange(ins,25,27)
    if opcode == 4 and testBit(ins, 20):
        base_reg = bitRange(ins, 16, 19)
        if base_reg == 13:
            reg_list = bitRange(ins, 0, 15)
            if testBit(reg_list, 0) and testBit(reg_list, 15):
                print('loaded r0 and PC from stack at 0x%x' % addr)
            if testBit(reg_list, 1) and testBit(reg_list, 15):
                print('loaded r1 and PC from stack at 0x%x' % addr)
            if testBit(reg_list, 2) and testBit(reg_list, 15):
                print('loaded r2 and PC from stack at 0x%x' % addr)
            
