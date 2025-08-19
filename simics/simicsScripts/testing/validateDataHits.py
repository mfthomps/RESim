from simics import *
import os
import sys
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import resimUtils


class ValidateDataHits():
    def __init__(self):
        self.cpu = None
        self.inject_hit_dict = {}
        self.my_hit_dict = {}
        self.break_addrs = []
        self.mem_map = {}
        self.hit_file = '/tmp/data_hits.txt'
        self.lgr = resimUtils.getLogger('validateDataHits', '/tmp', level=None)


        if not os.path.isfile(self.hit_file):
            print('No hit file at %s' % self.hit_file)
            return
        
        cmd = 'list-processors'
        result = SIM_run_command(cmd)
        for line in result:
            if '*' in line:
                print('got it %s' % line)
                cpu_str = line[0]
                self.cpu = SIM_get_object(cpu_str)
    
        if self.cpu is None:
            print('No cpu found')
            return
    
        with open(self.hit_file) as fh:
            for line in fh:
                addr_s, cycle_s = line.split()
                addr = int(addr_s, 16)
                cycle = int(cycle_s, 16)
                delta = cycle - self.cpu.cycles
                cmd = 'run-cycles 0x%x' % delta
                SIM_run_command(cmd)
                pc = self.getPC()
                self.lgr.debug('cycle now 0x%x wanted 0x%x pc 0x%x expected 0x%x' % (self.cpu.cycles, cycle, pc, addr))
                if self.cpu.cycles != cycle:
                    print('Wrong cycle, got 0x%x expected 0x%x' % (self.cpu.cycles, cycle))
                if pc != addr:
                    print('Wrong PC, got 0x%x expected 0x%x' % (pc, addr))

    def getPC(self):
        reg_num = self.cpu.iface.int_register.get_number('pc')
        reg_value = self.cpu.iface.int_register.read(reg_num)
        return reg_value

       
test = ValidateDataHits() 
print('Now run')
SIM_continue(100000000)
print('Done, do validate')
