Automated test of some RESim functions.  
Run this from the parent directory of where a temporary Simics
workspace should be created.  

tstcadet.sh is the top level script, which creates a workspace directory
and copies the necessary files into it.
The ubuntu_driver.ini file is altered to run cadet.simics as the initial
script, and to run teecadet.sh as the driver's interactive script.

The target runs cadet01 as a service.  The tests will first use
debugProc followed by a continue for some cycles to create a snapshot
after the cadet server is initialialized.

Scripts rely on xdotool.
