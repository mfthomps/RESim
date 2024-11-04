import idautils
import ida_bytes
'''
Patch up calls to external refs that get lost after rebasing 
arm programs (vxworks?)
'''
seg_struct = ida_segment.segment_t()
seg_struct = ida_segment.get_segm_by_name('extern')
addr = seg_struct.start_ea
size = seg_struct.size()
end_addr = addr+size
print('extern addr 0x%x size 0x%x' % (addr, size))

for seg_ea in range(addr, end_addr):
  
      for xref in idautils.XrefsTo(seg_ea):
           fun_name = ida_funcs.get_func_name(seg_ea)
           #print('seg_ea 0x%x xref_frm 0x%x to 0x%x %s' % (seg_ea, xref.frm, xref.to, fun_name))
           ida_bytes.set_forced_operand(xref.frm, 0, fun_name)




print("DONE***********")
