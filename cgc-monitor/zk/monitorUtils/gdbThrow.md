% gdbThrow(1) Cyber Grand Challenge Monitoring Utilities
% Mike Thompson <mfthomps@nps.edu>
% May 31, 2015
# NAME

gdbThrow -- Run a given CB / replay pair under Simics and invoke gdb if a pov scores

# SYNOPSIS

gdbThrow pov cb

# DESCRIPTION
Runs the named *cb* with the given *pov* using cgc-replay.  If a crash
is found, gdb is started.  Once in gdb, use "apropos reverse"

*NOTE* When you first get the gdb prompt, type:

    cgc

This will load directories and do the remote connect.  The gdb auto run
of initial commands is not reliable.

The *pov* is either a local file, or the name of a reference POV. 
The *cb* is the cb name, with a "CB" prefix, a binary count suffix,
and an optional "_MG" suffix if the patched binary is to be run.  For examples:

    CBCADET_0000101_MG

Would name the patched version of CADET_00001

If the *pov* is a local file, any name will do.  To name a reference POV,
use the convention:

    POV_CBCADET_0000101_ATH_000000

to name the first reference POV for that CB.

Example:

    gdbThrow somepov.xml CBCADET_0000101_MG

The *gdbThrow* program makes use of the CGC monitor (Simics) services, 
typically several instances to serve multiple sessions on the same host).
In the event of hangs, or other problems, the service can be cycled with:

    shutdownMonitor
    sudo /etc/init.d/monitorSlaveService start

Cycling the CGC monitor will disrupt other system users -- however YOU are likely
the only user at this time.

The source & symbols used by gdb are found in /mnt/vmLib/bigstuff/csetSymbols.
Note the desired files will be under the "build" directory -- and, in the case
of multi-binary executables, the cb_n/build directory.

The code executed within the simulated target is found in /mnt/vmLib/cgcForensicsRepo/CBs/v1.
*NOTE:* The system does not currently confirm the consistency between these two code sources.

# LIMITATIONS
Some PoVs may take a very long time to land, and some may even timeout before landing.
*However*: there are multiple copies of the CGC service running, so starting gdbThrow
from a different session would allow a bit of multitasking.

# COPYRIGHT
Created by employees of the US Government, cannot be copyrighted.

# SEE ALSO
    listRepo [cb] 
    shutdownMonitor
    /etc/init.d/monitorSlaveService start
