% targetWatcher(1) Cyber Grand Challenge Monitoring Services
% Mike Thompson <mfthomps@nps.edu>
% March 18, 2015
# NAME

targetWatcher --  create putPackages instances to feed target monitors

# SYNOPSIS

targetWatcher num_slaves

# DESCRIPTION

targetWatcher -- Watch for target monitors coming online and create putPackages
instances to feed them.  And kill the putPackages when the monitors go down.
In addition to creating putPackages, the targetWatcher may create a coroner
to watch for dead monitors and process any replays they had locked.

    num_slaves is the quantity of slaves created on this host.  If it is less
    than two, then no coroner will be created.

A single targetWatcher is intended to execute on each host.

# COPYRIGHT
Created by employees of the US Government, cannot be copyrighted.
