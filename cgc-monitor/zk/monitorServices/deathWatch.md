% deathWatch(1) Cyber Grand Challenge Monitoring Services
% Mike Thompson <mfthomps@nps.edu>
% March 18, 2015
# NAME

deathWatch --  Watch for failed monitors and finish their work

# SYNOPSIS

deathWatch instance

# DESCRIPTION

deathWatch -- Watch for failed monitors, i.e., locks that come and go
    but lack corresponding "done" nodes.  When found, get the replay
    associated with the lock and enqueue it for consumption by
    the target monitor for the given instance.

    instance -- indicates which monitor instance will be fed by this
    deathWatch.  Instances correspond to specific Simics workspaces.

A single deathWatch is intended to run on one or more hosts, depending
on the quantity of coroners specified in the configMgr.

# COPYRIGHT
Created by employees of the US Government, cannot be copyrighted.
