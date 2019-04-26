#CGC Forensic System Architecture and Interfaces#

The system includes a master server and a set of Monitor Slaves, each of which is 
allocated to a blade server.  A single blade server can host several Monitor Slaves.
Each Monitor Slave includes a Simics target environment and one
simulated host that it monitors.  Monitor Slaves are identical, except for their IP
addresses, (and a suffix to distinguish slaves that share a single blade).  
Each simulated host is identical, and boots from a common read-only disk
image (Simics .craff format) that is automatically replicated onto each 
blade from a NFS share.  

The master server is a set of services and utilities that run on one of the
blades.  These are intended to be migrateable to any of the blades.  The 
master services include:
* Clients that query external data stores (e.g., the CQE database) to retrieve
replacement CBs & PoVs for enqueuing for processing by the monitors.
* An exported NFS volume hosting a CB/PoV/Poller repository and a repository
of code and data used by the monitor slaves.
* The ZooKeeper service (TBD allocated to multiple blades as a cluster), which
provides distributed coordination of the various applications that make up
the fornensics system.
* MySQL service for logging results and system events.  (Note the ZooKeeper
hierarchy is the authoritative record until an after-the-fact audit confirms
that that mysql database has been fully archived.)
* A master controlling command line (zkMaster) interface for corse control
of the slaves, (e.g., list them; reset their services; power them off...)
* A set of reporting utilities that display status and results of replays.
* APIs to support analysis and visualization through replay of selected CBs
with selected PoVs or Polls. Ingest and results reporting is to external
systems, (e.g., via NFS files and ZooKeeper-based scripts).

## Simulated Targets ##
The operating system of the simulated hosts are initially configured with an initReplay.sh 
service that initiates a chain of scripts that result in execution of a replay service.  
The simulated host must include a minimum set of scripts to 
support a bootstrap -- all other scripts and data are retrieved from the slave via TFTP
susequent to boot.  In addition to initReplay.sh, the minimal scripts include dodate.sh, 
which sets the date on the simulated target;
doTFTP.sh which grabs a tar file; and runReplayMaster.sh, which uses those scripts and then
starts the replay_master executable (a copy of which is copied to the simulated host
on each boot).

The simulated host uses TFTP to obtain the tarball described above.  The service address
is given as 10.10.0.1, which translates to a Simics-defined simulated network node.  Simics
translates this to the workspace directory on the server that is running Simics.  
A "workspace" is a Simics construct, which is simply the directory from which a Simics 
instance is launched.  Each Monitor Slave has its own Simics workspace directory, which includes a 
repository for the the simulated target's bootstrap tarball and is home to a local copy of the CBs, PoVs and
polls that the simulate host will consume.  The workspace also contains a set of log files created during
monitoring (TBD remove statement when migration to common logs directory is complete).

As part of the simulated target's initial script chain, it locates kernel 
text sections and sizes (which may change between boots).  These are sent via TFTP to the 
Simics host's workspace directory for use by the monitor functions.  

The simulated host script/code chain is as follows:
    /etc/init.d/initReplay.sh
    ~/doreplay.sh -- wait for os boot to complete (getty)
    ~/runReplayMaster.sh -- eventually start the replay_master executable
       -- finalSetup.sh -- run ksections.py and put results into host workspace
    ~/replay/replay_master -- use ZooKeeper to get packages to run

The replay_master executable on the simulated target obtains configuration information
from a per-target zookeeper node that is currently loaded with the configuration values
from the zk/py/replay_master.xml file.  This node is created by the monitorSlaveBootstrap.sh script.
The node is deleted to force the target to TFTP its logs to the montor's workspace directory.


## Monitor Slaves ##
The implementation of a Monitor Slave is within the cgcMonitor.py script (and the dozens of scripts
within simics/simicsScripts that it calls).  It uses Simics breakpoints and callbacks to 
monitor the simulated target as described in [overview.html]. The quantity of Monitor Slaves created on any
given server (blade) is controlled by entries in the /mnt/vmLib/cgcForensicsRepo/licenses/ directory, which is
constrained by the Simics license found in that directory (current default is eleven per blade server).  
Creation of Monitor Slaves is controlled by the 
monitorSlaveBootstrap.sh script, which is invoked by the monitorSlaveService in /etc/init.d.  

The monitorSlaveBootstrap.sh script will also create one targetWatch.sh script on each host.  This targetWatch.sh 
script manages creation of putPackages.py scripts to feed replays to the monitor slaves as soon as the monitor slaves 
have completed their initialization.  The putPackages.py scripts watch the ZooKeeper hierarchy of CBs, polls and PoVs.  
The multiple instances of putPackages.py on each of the montitor slave hosts (blade servers) use ZooKeeper 
ephemeral nodes as locks to enforce exclusion on the consumption of replays.  One or more replays for a given
CB are packaged together and provided to the corresponding monitor slave using a separate ZooKeeper node hierarchy.
Currently putPackages.py includes two types of configurable packages.  The first is simply one replay per package.  The other 
configuration causes all uncompleted replays for a given CB to be put into the same package.  This latter 
configuration has some performance advantage because the CB is only copied once and the same replay instance can
be reused to launch the CB multiple times on the simulated target. 

In addition to creating putPackages.py scripts for each monitor slave, the targetWatch.py script will also 
allocate deathWatch.py scripts to a configurable number of monitor slaves (instead of putPackages.py scripts) .  
These deathWatch.py scripts watch all locks and respond to deletion of a lock on a replay that
has not completed (thus indicating the demise of a monitor slave).  In such an event, the deathWatch.py 
provides its associated monitor slave with a package for that replay.  At most, one deathWatch.py script is 
created on any monitor host.

The putPackages.py script uses the getMonitor.py module, which walks the ZooKeeper node hierarchy looking for CB/replay 
pairs that have not been executed.  The getMonitor.py module makes use of the teamSets.py module to sequence its 
consumption of CB/replay pairs as described in the section [Work Flow for CQE (and scored events)].  

When putPackages.py submits a package for processing by the monitor, (via the ZooKeeper), it is a ZooKeeper client on
the simulated target that detects the new package and commences execution of the replays named in the package. The 
cgcMonitor.py does interact with packages, however it does detect the new processes executing, and signals the completion 
of replay processing by updating the primary ZooKeeper replay nodes. 


## Fault Tolerance ##
The use of ephemeral ZooKeeper nodes for locks enables the deathWatch scripts to detect and respond to failure events. 
If a blade server fails, any replays locked by its monitors will be detected by deathWatch scripts and the replays will be
requeued for completion.
If a simulated host hangs while processing a replay, the associated putPackages script will detect it (via lack of new
monior log entries), and will exit the process, thus causing the held lock to be deleted, which will be detected by
a deathWatch script.

## Development & Maintenance ##
Most of the software is Python.  Master services running on the simulated targets are written in C.
The zkMaster shell and the zkShell services are Java.  Initial services and some utilities are bash.

The development system is currently separate from the blades that run the master and slave monitors.
The development system has a subversion repository (cgc/users/mft).  It mounts the /mnt/vmLib NFS share
exported by the master monitor, and uses this to drop tarballs of code for consumption by the blades.

The development system includes local monitors for testing.  Most testing and debugging occurs with a single monitor
executed from /mnt/simics/simicsWorkspace0 via the monitorDev.sh script,  which consumes code directly from the svn 
repository.  The exception is code executed within the simulated targets, which must be packaged using the tools that
package code for use by non-development monitors as described in the next paragraph.

Whenever code is changed, the collectSlaveRepo.sh must be run to gather code onto the NFS share for use by the monitors.
All code is obtained from the development system, except for the replayMaster and (optionally) the replayService executables
that run on the simulated target hosts.  These are currently built on a VirtualBox based debian host that moves the
executables to the vmLib/cgcForensics repository using the updateRepo.sh script.  The monitorSlaveBootstrap.sh (and its
per-monitor child processes) copy this code to its target locations. [something about the "monitorSlaveBootstrap.sh none"  
not 


## Work Flow for CQE (and scored events) ##
Forensics monitoring for CQE requires that the following vetting occur on competitor-provided replacement binaries and
PoVs:
    Each replacement binary set will consume three service polls, selected for their depth of code coverage;
    Each competitor-provided PoV will be run against the original (vulnerable) CB.


In preparation for CQE (or a scored event), all selected vulnerable author-generated CBs and selected service polls are copied 
into a file system (NFS) shared by each of the monitor hosts.  Each team submittal set ("team set") is then retrieved from
the central CQE database via the fdRepo.py script.  Replacement CB binaries and the PoV are copied into the file repository.
The set is enqueued for processing using the teamSet.py module, which creates a ZooKeeper node for each 
set, containing a list of CB/replay pairs that must be processed for that set.  The ZooKeeper CBs hieararchy is then 
updated to reflect each CB/replay pair, with the name of the team set node written as data into the replay node.  (Note that
getMonitor consumers may try to get a lock on a CB/replay before that CB or replay node has been created.  In such a case,
the monitor reverts to a broad search of the CBs hierarchy, using watchers to be notified when new replays have been added.)
The forensics mysql database is then updated with an entry for the team submission.

The putPackages.py script running on behalf of each monitor references the team set nodes to sequence their consumption of
CB/replay pairs.  When a monitor completes processing of a CB/replay pair, it reads the team set name from the replay node
and, if it is the final pair in the set, a "set_done" node is created off the team set node to indicate processing has 
completed.  Note, this is the point at which vetting is decided, and the set_done node is not created if vetting fails.

The updateSQL.py service watches team set nodes for completion, and updates the CQE database to reflect that a team set has been vetted.
Similarly, the updateDBLogs.py service watches replay nodes and updates the forensics database (mysql) with results from each replay.


# Analysis #
clearThrows.py  -- remove analysis results from the Ida queue
tthrow.py -- start Ida for the next analysis in the Ida queue
tbd description of install tools on macbook, e.g., 
sudo easy_install kazoo
sudo easy_install pymysql
Ida w/ cgc loader


# Record of replays #
Which events are monitored and which artifacts are created depends on the runtime configuration reflected
in the master.cfg file.  A checksum of this file is maintained by the various functions to ensure that replays
are processed using the intended configuration.
The replay table contains records of each replay, drawn from the ZooKeeper replay "done" nodes by the updateDBLogs.py script.
This table is read by the reportSQL.py script when genrerating summary reports.  
Each replay table entry includes a "config" field
that holds the checksum of the master.cfg file used when running the replay.  The database holding the replay table is named in the 
configMgr.py module, and this same database stores related tables, e.g., the team submissions.  It is expected that each event,
(testing or actual), will have its own database.  Multiple runs would typically use differing configurations.  For example, a
bare-bones forensics run would use a configuration that only checks for kernel and "player" exploitation.  A subsequent "cross product" run 
that pits each PoV against each replacement CB would include no monitoring beyond the recording of the PoV success.  That run might
be followed by a run of each successful PoV, and that run would monitor events such as execution of non-executable code.  Between each run of
the same replay, it is 
expected that the ZooKeeper records will be moved to the sql database.  Each new run for a given replay will commence by deleting the 
associated replay node (and its done node).

The user-selected master.cfg file is placed into a ZooKeeper node by functions that enqueue new sets of replays, (and by the initial resetting 
of the primary ZooKeeper hierarchy.)  When the cgcMonitor initiates, it records the configuration checksum in its monitor status node,
which is referenced by the putPackages.py when it starts, and whenever it is idle for five seconds.  If the configuration changes, it
deletes the cgcMonitor's monitor status node, which causes the cgcMonitor to reinitialized using the new configuration.  Additionally,
whenever a replay is enqueued, (i.e., a replay node created beneath a CB node), the configuraiton checksum is recorded in that node.
The putPackages module will ignore replays whose configuration checksum does not match its current checksum. 

