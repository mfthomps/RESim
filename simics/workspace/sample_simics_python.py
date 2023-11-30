'''
Sample ad-hoc simics script that gets the current cpu and then uses it to 
find stuff where RSP becomes greater than 0x300000
'''
cmd = 'list-processors'
result = SIM_run_command(cmd)
cpu = None
for line in result:
    if '*' in line:
        print('got it %s' % line)
        cpu_str = line[0]
        cpu = SIM_get_object(cpu_str)

if cpu is None:
    print('No cpu found')
else:
    rip_reg_num = cpu.iface.int_register.get_number('rip')
    rsp_reg_num = cpu.iface.int_register.get_number('rsp')

    done = False
    limit = 1000
    for i in range(limit):
        next_cycle = cpu.cycles+1
        cmd = 'skip-to cycle = 0x%x' % next_cycle
        SIM_run_command(cmd)
        rip_reg_value = cpu.iface.int_register.read(rip_reg_num)
        rsp_reg_value = cpu.iface.int_register.read(rsp_reg_num)
        print('rip: 0x%x rsp: 0x%x' % (rip_reg_value, rsp_reg_value))
        if rsp_reg_value > 0x300000:
            break
