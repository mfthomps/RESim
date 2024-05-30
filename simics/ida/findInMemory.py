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

seg_struct = ida_segment.segment_t()
seg_struct = ida_segment.get_segm_by_name('abs')
addr = seg_struct.start_ea
#size = seg_struct.size()
#end_addr = addr+size
addr = 0x9a00000
size = 0xf0000
end_addr = addr+size
print('addr 0x%x size 0x%x' % (addr, size))

for seg_ea in range(addr, end_addr):
  val = idc.get_wide_dword(seg_ea)
  if val >= 0xb7100000 and val <= 0xb7200000:
      print('GOT IT val 0x%x at 0x%x' % (val, seg_ea))
  
      #for xref in idautils.XrefsTo(seg_ea):
      #  print("Found a cross reference {}: from {} to '.idata' variable {}".format(xref, xref.frm, seg_ea))

seg_struct = ida_segment.segment_t()

print("DONE***********")
