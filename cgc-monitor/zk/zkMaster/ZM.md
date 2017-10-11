% ZM (1) Cyber Grand Challenge Monitoring
% Mike Thompson <mfthomps@nps.edu>
% May 6, 2016
# NAME

ZM -- cgc-monitor zookeeper master program


# DESCRIPTION

The cgc-monitor Zookeeper Master program (ZM) interacts with
all the monitors via shared zookeeper nodes.  It accepts the
following commands, either as parameters, or command line input.

	(l)ist -- show ready monitors
	lh -- list hosts listening to this master
	start -- start all monitors
	clean -- stop all monitors
	critical -- show critical log entries
	(q)uit -- quit this program
	Any other command will be passed to and executed by the target zkshell service.

The final entry above can be used like a parallel-ssh function to perform commands on 
whatever set of monitors is up and listening.

Also see man pages for the following utilities:

    reportSQL -- report on progress via queries to the monitor local database.
    listMonitor -- status of replays and submissions as reflected in the zookeeper nodes.
    monitorUtils -- housekeeping of databases, repo files and zookeeper nodes.


# COPYRIGHT
Created by employees of the US Government, cannot be copyrighted.


