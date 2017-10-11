from simics import *
import mod_software_tracker_commands as tr
import sys
sys.path.append("/home/mike/simics-4.6/simics-4.6.84/linux64/lib/") 
sys.path.append("/home/mike/simics-4.6/simics-4.6.84/linux64/lib/software-tracker")
import logging
import startDebugging2
'''
    Install a hap that will run when execution resumes.
    Its purpose is to install a hap that fires when execution
    again stops.
'''
class startDebugging1x5():
    __start_hap = None
    '''
    
    '''
    def __init__(self, dbi):
        SIM_run_alone(self.install_start_hap, dbi)

    def install_start_hap(self, dbi):
        self.__start_hap = SIM_hap_add_callback("Core_Continuation", 
		    self.start_callback, dbi)

    def delete_start_hap(self, dum):
        SIM_hap_delete_callback_id("Core_Continuation", self.__start_hap)
        print 'the start hap has been deleted'

    def start_callback(self, dbi, one):
        SIM_run_alone(self.delete_start_hap, None)
        print 'in start callback startDebugging1x5'
        startDebugging2.startDebugging2(dbi)
        
        
