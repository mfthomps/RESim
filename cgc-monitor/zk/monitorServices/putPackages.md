% putPackages(1) Cyber Grand Challenge Monitoring Services
% Mike Thompson <mfthomps@nps.edu>
% March 18, 2015
# NAME

putPackages -- Find replays that have been enqueued and package them for consumption by the target

# SYNOPSIS

putPackages [instance] [dbg_queue] [no_monitor]

# DESCRIPTION

Consume from the queue of replays (or optionaly the debug queue) and package the
entries for consumption by the target working for the given instance

    instance -- the target instance that will be fed packages, defaults to zero
    debug -- consume entries from the debug queue (e.g., for Ida client)
    no_monitor -- do not check that the monitor for the given instance is ready (primarily for testing

# COPYRIGHT
Created by employees of the US Government, cannot be copyrighted.
