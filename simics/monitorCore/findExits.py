did_eip = []
def getRegValue(cpu, reg):
    reg_num = cpu.iface.int_register.get_number(reg)
    reg_value = cpu.iface.int_register.read(reg_num)
    return reg_value

def modeChanged(want_pid, one, old, new):
   global did_eip
   if new == Sim_CPU_Mode_Supervisor:
       #print('in super')
       pass
   else:
       #print('in user')
       eip = getRegValue(cpu, 'rip')
       if eip not in did_eip:
           instruct = SIM_disassemble_address(cpu, eip, 1, 0)
           print('0x%x  ins: %s' % (eip, instruct[1]))
           #SIM_break_simulation('mode changed')
           did_eip.append(eip)

cpu = SIM_current_processor() 
mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", cpu, 0, modeChanged, None)
 
