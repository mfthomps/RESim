'''
An example HAP callback that catches execution of the magic instruction,
which is cpuid on the x86.
'''
from simics import *
import mftUtils
sig_break = None
class break_test():
    def __init__(self):
        cb_num = SIM_hap_add_callback("Core_Magic_Instruction", 
		self.magic_callback, None)
        print("set magic hap to callback id %d" % cb_num)
    def magic_callback(self, data, third, forth):
        print("got magic break ")
	SIM_break_simulation("stopping...")
break_test()
