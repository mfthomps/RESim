README for accessing the CGC forensic monitoring system via a local Ida client. Version (0.05)

## Overview ##
The CGC Monitor Ida Client remotely executes challenge binaries within a CGC Monitor environment,
controlled via the Ida Pro gdb debugger.  Support includes reverse execution to breakpoints,
bookmarks and a variety of shortcuts (e.g., run backwards until the address pointed to by
ESP is modified).  The CGC Monitor is accessed as a remote service, with the Ida Client 
running on a CGC referee workstation or CGC laptop.  

Sessions are initiated using the "oneThrow.py" command, via which you can name
the desired session in terms of its CSID, round, throwing team, and defending team.
For example:

    oneThrow.py KPRCA_00065 34 5 7

will replay team 5's POV against team 7's defense of KPRCA\_00065 in round 34.
A specific throw number can be named using the "-s" option prior to the CSID,
and throw numbers are zero-indexed.

A brief screen movie of the tool backtracking through a Type 2 PoV is at: 
[space/~mfthomps/idaClient/type2Pov.mp4](space/~mfthomps/idaClient/type2Pov.mp4)

## Prerequisites  ##
Prerequisites (ZooKeeper Client [Netflix python bindings] and Mysql clients for Python):
    
*    sudo apt-get install python-setuptools  (only need if not using "easy\_install" below) 
*    sudo easy\_install kazoo  (or install from 
[http://space/~mfthomps/python\_packages/kazoo-2.2.1.tar.gz](http://space/~mfthomps/python_packages/kazoo-2.2.1.tar.gz)

*    sudo easy\_install pymysql (or install from 
[http://space/~mfthomps/python\_packages/PyMySQL-0.7.3.tar.gz](http://space/~mfthomps/python_packages/PyMySQL-0.7.3.tar.gz) 
)

*   Ida, with the cgc loader (loader included in this distribution)

## Installation ##
For a linux (e.g., ref workstation):

*   Get the idaClient .deb package from 
[http://space/~mfthomps/idaClient/cgc-monitor-ida-client\_0.1\_amd64.deb](http://space/~mfthomps/idaClient/cgc-monitor-ida-client_0.1_amd64.deb)
    and install it.

*   Then run update-cgc-monitor, which will fetch and install other packages from the cgc-dev build-artifacts (and this will
    fetch and install the ssh key needed to access the monitor -- use the standard cgc-dev password to unlock the key when prompted).


# ssh key and config #
Your linux or OSX client will need some entries in your ~/.ssh/config file as follows.
The id\_cgc\_user key will have been installed during the installation step.
    
    Host localmonitor
          HostName 127.0.0.1
          User cgc
          IdentityFile ~/.ssh/id_cgc_user
    
    Host 10.20.200.10* 10.20.200.11* 10.20.200.20* 10.20.200.21*
       User cgc
       IdentityFile ~/.ssh/id_cgc_user
       ProxyCommand ssh -q localmonitor nc %h 22
    
    Host bladecgc
      HostName 10.20.200.101
      User cgc
      IdentityFile ~/.ssh/id_cgc_user
    
## Running ##
Access to the CGC Monitor system is via ssh forwarding proxies. Start them with:

    checkProxies.sh

Kill them with:
    
    killProxies.sh

When you run a oneThrow.py ...json command,
it may take a moment for Ida to start.  Note, on the MacBook, Ida starts with a dialog
that may be hidden by other windows.  Look for the bouncing Ida icon on your
OSX toolbar.

Use the *Ida Help* menu to find help for the CGC Ida Client.
Use the *Ida Debug* menu to see reversing commands (and their hotkeys).

## Ida Client Usage Notes ##
When Ida starts, execution is at the instruction that faults or scores a PoV.  
Use <alt><shift>m to see the message from the cgcMonitor.  Faults will include
the stack frame.  

Use [alt][shift]q to quit, otherwise Simics monitors may hang and become unavailable for 
future use.

The system will scp CBs onto your computer, within a subdirectory, (named "stage") from where
you run oneThrow.py.  Ida databases are placed there as well.

The tool supports bookmarking whereby you can set and later jump back to selected
points in the execution of the binary. See the "Bookmarks" tabbed window.  (These 
bookmarks do not persist across sessions [yet]).

The first bookmark is set at _start+1 to avoid dealing with page faults.
If you manage to step into the kernel (e.g., encounter a page fault), you can run to user space via
[alt][shift]u.

The "uncall" function can be very slow, particularly if there are lots of call/returns in the
function you are uncalling from.  If Ida analysis works, it will reverse to the start of the
function and then back one.  Otherwise prepare to wait.

Start monitor

    cd /mnt/simics/simicsWorkspace6
    monitorDebug.sh

Stop 

    ^c  or killSimicsWorkspace 6

    clearPackages 6

Logs

    cd /mnt/cgc/logs/monitors
    tail -f *6*.log


Ida quietly exits when its idb is bad -- may need to delete that from the clients stage directory.

## Alternate session naming ##
CFE competitor submissions can be replayed
by naming the forensics json file found via the forensicsMap.py function.  For example, to find the 
forensics json for the team #1 throw against team# 2 in round 3 for CROMU_00055:

    forensicsMap.py CROMU_00055 1 2 3

will yield:

    CBCROMU_0005501  5e666ff36b0a39e7a345e0d415fe4fb6feab671236ef292d1c5715c7bbe10c00.json

Then, replay the corresponding json using:

    oneThrow.py fe380c611a14464754952b88ff138e942fe558068125df6c5bfd06209437d3f8.json

This will replay the pov against the appropriate RCB using whatever IDS rules were deployed.  The
default is the first throw.  The second throw would be using the "-s 1" option (yeah, zero relative).

## Deploying the CGC Monitor for Ida Client Sessions ##
Use of the Ida Client requires one or more CGC Monitor targets to be running in the debugging configuration.
To achive this, run

    monitorDebug.sh

from a CGC Monitor target's Simics workspace diretory, e.g, 

    /mnt/simics/simicsWorkspace6

Use of tmux is suggested if multiple sessions are to be supported.
