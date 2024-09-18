import idc
import idautils
import ida_bytes
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import decodeArm as decode
'''
Patch up calls to fun refs that get lost after rebasing 
arm programs (vxworks?)
'''
seg_struct = ida_segment.segment_t()
seg_struct = ida_segment.get_segm_by_name('.text')
addr = seg_struct.start_ea
size = seg_struct.size()
end_addr = addr+size
print('fun addr 0x%x size 0x%x' % (addr, size))

for seg_ea in range(addr, end_addr):
   fun_name = ida_funcs.get_func_name(seg_ea)
   if fun_name is not None:
      for xref in idautils.XrefsTo(seg_ea):
           instruct = idc.GetDisasm(xref.frm)
           mn = decode.getMn(instruct)

           if mn == 'BL':
               op2, op1 = decode.getOperands(instruct)
               call_to = None
               try: 
                   call_to = int(op1, 16)
               except:
                   pass
               if call_to == seg_ea:
                   print('seg_ea 0x%x xref_frm 0x%x to 0x%x %s instruct: %s' % (seg_ea, xref.frm, seg_ea, fun_name, instruct))
                   ida_bytes.set_forced_operand(xref.frm, 0, fun_name)




print("DONE***********")
