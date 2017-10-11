% reportSQL(1) Cyber Grand Challenge Monitoring Utilities
% Mike Thompson <mfthomps@nps.edu>
% March 18, 2015
# NAME

listMonitor -- Query the state of the monitor as reflected in
the zookeeper nodes.

# SYNOPSIS

listMonitor [option]

# DESCRIPTION
Query the state of the monitor CBs, replays and team sets as reflected
in the zookeeper nodes.  

# OPTIONS
lc [-v] | [-i] 
:   list CBs. Use -v to list all replays for each cb & their status.  Use -i for only the locked replays
lr CB [log] 
:   list povs/polls for given a cb and optionally display the log entires
al 
:   list all povs/polls for all cbs with log entires
lu 
:   list unlocked CBs
lp instance [all] 
:   packages not yet done for the named instance on this host [all] for packages done or not
lts [log | set_id | -i | not_cleared] 
:   Display a summary of team sets.  Use *log* to displays logs, *set_id* shows just that submission, -i filters for submissions
that have not yet completed.  The not_cleared optoin filters for submissions that failed vetting.
lrp *replay* 
:   log entries for all replacements polled by a service poll or PoV per the given *replay*
sum 
:   display the quantity of CBs and PoVs

# COPYRIGHT
Created by employees of the US Government, cannot be copyrighted.

# SEE ALSO
    reportSQL
    monitorUtils
