% reportSQL(1) Cyber Grand Challenge Monitoring Utilities
% Mike Thompson <mfthomps@nps.edu>
% March 18, 2015
# NAME

shutdownMonitor -- Kill all monitor services, including Simics instances on a host.

# SYNOPSIS

shutdownMonitor

# DESCRIPTION
First, the targets are signaled that a shutdown is occuring, giving them
a chance to scp their logs to the host.  Then the 

    /etc/init.d/monitorSlaveService clean 

is invoked.  Note, this is a host-local operation.  See stopMonitor for
system wide effects.

# COPYRIGHT
Created by employees of the US Government, cannot be copyrighted.

# SEE ALSO
    runEvent
    stopMonitor
