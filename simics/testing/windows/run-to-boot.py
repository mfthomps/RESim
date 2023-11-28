cmd = 'board.get-processor-list'
proclist = SIM_run_command(cmd)
cpu = SIM_get_object(proclist[0])
SIM_run_command('pselect %s' % cpu.name)
cmd = 'r count=11460387259 unit=steps'
SIM_run_command(cmd)
print('back from continue')
cmd = 'write-configuration booted_test'
SIM_run_command(cmd)
SIM_run_command('quit')
