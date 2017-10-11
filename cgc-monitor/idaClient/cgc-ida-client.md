README for accessing the CGC forensic monitoring system via a local Ida client. Version (0.05)

## Overview ##
The CGC Monitor Ida Client remotely executes challenge binaries within a CGC Monitor environment,
controlled via the Ida Pro gdb debugger.  Support includes reverse execution to breakpoints,
bookmarks and a variety of shortcuts (e.g., run backwards until the address pointed to by
ESP is modified).  The CGC Monitor is accessed as a remote service, with the Ida Client 
running on a CGC referee workstation or CGC laptop.  The user selects a CB / replay pair that is already in
the CGC Monitor repository, (as listed by the "lRepo -v" command).

A brief screen movie of the tool backtracking through a Type 2 PoV is at: 
[localhost:8080/~mfthomps/idaClient/type2Pov.mp4](localhost:8080/~mfthomps/idaClient/type2Pov.mp4)

## Installation ##
Prerequisites (ZooKeeper and Mysql clients for Python):

    sudo easy_install kazoo
    sudo easy_install pymysql

    Ida, with the cgc loader (loader included in this distribution)

For the Macbook:

    Get the cgcMonitorClient.tar.gz from 
    [localhost:8080/~mfthomps/idaClient/cgcMonitorClient.tar.gz](localhost:8080/~mfthomps/idaClient/cgcMonitorClient.tar.gz) 
    and expand it in a work directory.

    The tool expects a Mac (OSX) based idaq installed at "/Applications/IDA Pro 6.8/idaq.app/Contents/MacOS/idaq"
    Edit the startIda.sh script to customize. (The version matters, older version will not read the idb files).

For a linux (e.g., ref workstation):


# ssh key and config #
Your linux or OSX client will need some entries in your ~/.ssh/config file as follows.
Mofify the "bladecgc" entry per your user id and name for the gw1 box.
    
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
      # replace "cgcgw1" with your name for gw1
      ProxyCommand ssh -q YOUR_ID@cgcgw1 nc 10.20.200.101 22
      #ProxyCommand ssh -q mfthomps@cgcgw1 nc 10.20.200.101 22
    
## Running ##
Change directory to cgc-monitor/idaClient
and source the setPaths.sh script:

    source ./setPaths.sh

Ida should not be running.
List challenge binaries and their replays:

    lRepo -v

Use the Ida debugger to replay one of the listed replays:

    oneThrow.py <pov> <cb>

where *pov* is the PoV name and *cb* id is the CB name.
example:  

    oneThrow.py POV_CBCADET_0000301_ATH_000001  CBCADET_0000301

(Note the output of "lRepo -v" is intended to be cut/pasted after the 
oneThrow.py command)

It may take a moment for Ida to start.  Note, Ida starts with a dialog
that may be hidden by other windows.  Look for the bouncing Ida icon on your
OSX toolbar.

### NOTE: Initialization with Ida is sometimes not quite right, so, first do a 
[alt][shift]o to get Ida in synch with the simulated gdb server ###

Use the *Ida Help* menu to find help for the CGC Ida Client.
Use the *Ida Debug* menu to see reversing commands (and their hotkeys).

## Usage notes ##
When Ida starts, execution is at the instruction that faults or scores a PoV.  
Use <alt><shift>m to see the message from the cgcMonitor.  Faults will include
the stack frame.  

Use [alt][shift>q to quit, otherwise Simics monitors may hang and become unavailable for 
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
function you are uncalling from.  If the stack is trusted in the current context, use the
Ida debugger stack trace to jump to the calling function and then use "reverse-to-cursor", 
(alt-shift-f4).

The "Wrote to register" Debugger function runs backwards until the value in the named register
changes, e.g., adding zero to the register will not break execution.
