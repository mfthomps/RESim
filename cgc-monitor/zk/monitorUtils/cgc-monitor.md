% cgc-monitor (1) Cyber Grand Challenge Monitoring 
% Mike Thompson <mfthomps@nps.edu>
% May 6, 2016
# NAME

cgc-monitor  -- Overview of cgc-monitor CFE work flow and use


# DESCRIPTION

The cgc-monitor is a set of services and utility programs.
The monitor is managed from the master monitor, e.g.,
fenc601.

Monitoring event submissions is initiated via the

    runCFE <games_dir> <game>

command, where *games_dir* is the location of the cgc-forensics
config files and binaries pushed by the cgc workflow, and *game*
is an optional first game directory to start processing.
The runCFE command will reset all local storage and will initiate
retrieval of json files from the games_dir.  As new games appear,
they will be processed and recorded in a new database.

Monitoring is halted via:

    stopMonitor



Also see man pages for the following utilities:

    reportSQL -- report on progress via queries to the monitor local database.
    listMonitor -- status of replays and submissions as reflected in the zookeeper nodes.
    monitorUtils -- housekeeping of databases, repo files and zookeeper nodes.
    ZM -- zookeeper master, view target status and coordinate start/stop of targets



# COPYRIGHT
Created by employees of the US Government, cannot be copyrighted.

# SEE ALSO
reportSQL, listMonitor, ZM
