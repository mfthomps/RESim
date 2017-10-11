run_command('add-directory -prepend /mnt/cgc/simics/simicsScripts')
run_command('add-directory -prepend /usr/share/pyshared/simicsScripts/')
run_command('run-command-file targets/x86-x58-ich10/viper-debian.simics')

