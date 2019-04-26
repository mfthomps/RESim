# CQE Forensics Overview #

## Introduction ##
The CGC forensics system monitors the execution Challenge Binaries (CBs) and Proof of Vulnerability 
Emitters (povers).
User space and kernel space execution are monitored.  User space monitoring is intended to provide independent
evidence of PoVs or defenses, and to detect attempts to subvert the replay program's player process.
Kernel monioring is intended to detect attempts to subvert the CGC infrastructure.
Monitoring is organized around discrete sessions, i.e., the replay of one PoV or one service poller.  
Each session results in two artifacts: 

1) a summary [log](#log) containing a profile of the session, including [events](#forensic_events) of interest,
e.g., its termination; and, 

2) a syscall log containing all parameters and return values for each CB within the session.  

These artifacts are XML files.  Additionally, the monitor program generates a detailed log for debugging.
And the monitor includes options for generating detailed execution & memory access traces, though these 
can take a long time to complete.  

## The Monitor ##
The core of the forensics system is the "monitor", which is a Simics-based application that instruments
and reports on sessions execute on emulated computers.  In addition to monitoring CBs and PoVs, the monitor 
includes an analysis function that enables an analyist to interact with a CB or PoV via the Ida remote debugger.
The analysis function includes reverse execution to selected breakpoints, including shortcuts such as "reverse
to the instruction that previously modified the return address at the current ESP."

The forensics system scales by adding monitors, each of which consume CBs, service polls and PoVs from a 
common repository, (currently a NFS for testing purposes).  A shared queue is implemented using the ZooKeeper 
distributed application coordination service.  Initial collection of session results is also implemented
using ZooKeeper, providing a reliable record of session events.  

The primary controlling input to the monitor is a "package".  A package consists of the names of one CB 
(or mitigated CB) and one or more PoVs and/or service polls.  The monitor executes each corresponding session in
turn, and reports on each session as they complete.  Other inputs to the monitor include configuration 
data, e.g., the amount of monitoring to perform on each session.

A suite of supporting tools enqueue packages and report on results.  Packages can be explicitly defined, e.g., 
to monitor selected sessions, or package creation can be automated such that multiple monitors will 
cooperate to consume the entire set of potential sessions.  The tool suite includes test scripts for creating
a repository of CBs, PoVs and pollers from ad-hoc sources.

The monitor automatically generates its own configuration data for each CB in the repository, (e.g., text and 
data section locations).  And it generates kernel configuration information, (e.g., the offset of the 
syscall_call entry point) from the target kernel symbol table.

A reporting tool displays summary logs for selected sessions, and will be extended to provide summary information
to the CGC infrastructure.  The following example command lists the replay sessions for a CB named CB000002:
   
    $ ./listMonitor.py lr CB000002 log
    3 replays for CB000002      name              time  c_sys   r_sys  ctick   cutick   c_flt  r_flt  wall_time  event
    SP_CB000002_000001     
    2014-05-23 15:55:16  SP_CB000002_000001       5.05  150     118    512673  157937   2      14      0.00      
    SP_CB000002_000000     
    2014-05-23 15:55:04  SP_CB000002_000000       9.44  519     504    824541   80983   2       5      0.01      
    POV_CB000002_ATH_000000     
    2014-05-23 15:55:23  POV_CB000002_ATH_000000  5.69  555      72    258237   81015   1      15      0.10      USER_SIGSEGV
  
### Log entry fields <a id="log" />
    
    time 
    The amount of real time needed to monitor the session, exclusive of overhead time (e.g., it does
    not include the time required to create a new cb-server.)
    
    c_sys
    The quantity of system calls made by the CB process(es).
    
    r_sys
    The quantity of system calls made by the player process of the replay program, commencing at the
    parsing of the replay xml file.
    
    ctick
    The number of CPU cycles consumed by the CB process(es).
    
    cutick
    The number of CPU cycles consumed by the CB process(es) while in user space.
    
    c_flt
    The number of page faults encountered by the CB process(es).
    
    r_flt
    The number of page faults encountered by the player process.
    
    wall_time
    The elapsed session time from the perspective of the targets, i.e., as reported by the
    simulated real-time clock.
    
    event
    CB (or player) termination conditions.
 
### CGC forensics events <a id="forensic_events" />
The event field can be one of the following:
   
   Anticipated events

      USER_NO_X
      Execution of an address that is not within the text section of the CB.
      
      USER_ROP
      Return to an instruction that does not follow a call instruction in a CB.
      
      USER_SIGSEGV
      A segmentation violation (SIGSEGV) signal in user space of a CB.
      
      USER_SIGILL
      An illegal instruction (SIGILL) signal in user space of a CB.
    
      READ_PROTECTED_MEMORY
      Access to memory designated as protected (TBD)
  
      USER_SIGALRM
      An alarm (SIGALRM) signal in user space of a CB.
      
      USER_BAD_SYSCALL
      An undefined call to the CGCOS.
      
   Critial events indicating potential attempts to subvert the platform
      
      USER_SIG_OTHER
      Some other signal caught in a CB or in the player.
      
      KERNEL_NO_X
      Execution outside of the kernel text section and linked modules.
      
      KERNEL_ROP
      Return to an instruction that does not follow a call instruction within
      the kernel.
      
      KERNEL_CRED
      Modification of the authorization credentials for CB or player processes.
      Includes a switch to a credential having different user or group IDs as
      well as modifications to the credentials themselves.
      
      KERNEL_NOCALL
      Transfer of execution to selected kernel address ranges that should not
      be executed within CB or Player processes.  These include exec functions
      and networking [TBD].

What is monitored?
------------------
The monitor instruments and observes two kinds of CGC processes:
    1) Any process created by a cb-server process or the replay process having
       a name that begins with CB; and,
    2) Any process created by the replay process having the name "player".  These
       processes are monitored commencing with the parsing of the xml replay
       file, i.e., the point at which potentially malicious data is consumed.

The monitor uses Simics breakpoints and callbacks to detect the [events](#forensic_events) listed in
the previous section.  The monitor does not use Simics OS awareness functions, and thus do not incurr
the roughly 3x slowdown that would entail.  The monitor supports Linux 3.1.2 and FreeBSD 9.2 (TBD test for support of 10).

Additionally, the monitor will provide trace information and debug environments for arbitrary processes, as 
specified in the master.cfg file.

Running the Monitor
-------------------
The monitor is run as a service
as described in architecture.txt.  It can also be run as a single 
instance in the development environment via the monitorDev.sh 
script.

The monitor can also be run ad-hoc from within the Simics from the 
prompt, which requires path initialization and manual starting of
targets.  That is outside the scope of this document.

In any event, you will require some target systems running some software of interest,
and that is described in the section titled "Support Tools".

Tracing
-------
The tracing secion of the master.cfg file defines a target process whose execution is to result in the
creation of a Simics trace file.  This process need not be a CGC process.  A set of tools in the visualization
directory will combine trace files with system call logs into single file, ordered by cpu cycle.

Support Tools
=============
The script that performs the Simics simulation monitoring (cgcMonitor.py)
defines a set of callbacks that then monitor the simulated system from
within the Simics execution context.  The purpose of the
ZooKeeper based scripts described by this section is to automatically deploy
CBs, pollers and PoVs on the simulated hosts, so that there is something
for the monitor to observe.

This section describes the use of these scripts and a basic workflow.
See the Monitoring section of this document for a discussion of the forensics
monitoring functions.

These scripts assume a CB/PoV/Poller repository.  For testing, such
a repository is built via scripts in the simics/demoRepo directory.
For example, doSE1.sh builds a test repository of a set of sample CBs
created by CB authors for use in the first CGC scored event.   
Two different tools can be used to simulate
competitor submissions.  Each make use of the teamSets module, (described
in the [architecture.html] document), to interact with the monitoring
functions.  The competitorset.py script simply copies
author CBs and PoVs and renames them as if they came from competitors,
and then uses the teamSets module to enqueue the submissions.
The fdbDumbRepo.py script is similar, except it injests the CBs and
PoVs into a mysql database for extraction by a jigged-up version of
the fdbRepo.py script, which extracts submissions from the mysql database
(as if they came from the CQE Foundation DB), and enqueues them using the 
teamSet module.  Both approaches create simulated submissions consisting 
of replacement CBs and PoVs, using the sample CB items as templates.

Once this simulated repository is in place (and as it grows), the 
putPackages.py script is used to enqueue selected CB/replay pairs 
for consumption by the monitors.  The demoRepo/one.sh script uses
putPackages to enqueue individual CB/replay packages, e.g., for 
testing and one-off analysis.  If orignial author CBs or PoVs are
to be run, then the updateTree.py script should first be used to
update the CB node hierarchy to include author submissions.

See the architecture.txt document for a description of how putPackages.py
is used by the monitor slave services during productions runs.

The simulated hosts that run CBs, PoVs and Pollers
use the replay process, (for local replays), or the replay and
cb-server processes, (for remote replays).  The replay and cb-server
processes are created by master processes that take direction from
the packages enqueued via ZooKeeper nodes.  These masters are
created via the updateReplay.sh and updateServer.sh scripts,
which are run on the simulated hosts.  For
local replays, only the updateReplay.sh script is used.  The
replayMaster.xml and serviceMaster.xml configure the masters.
These configurations are deployed via putReplayCfg.py and
putServiceCfg.py.  Only the former is used if replays are local.

User Interface Tools
--------------------
The listMonitor.py script displays information about the CGC
node hierarchy and the results of replays.

The reportSQL script displays information recorded in
the mysql database.

The ZM.sh script starts the zkMaster shell, which lets the
user start, stop and query the status of the monitor slaves.
It can also be used to execute system commands on each of the
blade servers, e.g., to power off the servers.

monitorUtils.py removes incomplete replays and locks.

## Logs ##
Logs are generally located in the /mnt/cgc/logs directories.  Logs include:
* monitor_N  -- information and debugging generated by the cgcMonitor. These
are found in cgc/logs/monitors, one file per monitor on the blade. Logging level is
controlled in the master.cfg file.
* packages_N -- generated by the putPackages scripts as they feed replays to monitors.
* monitorSlaveService.log -- from the monitorSlaveBootstrap running on each blade.
* monitorSlaveServiceN.log -- continuation of the log, starting at the per-slave launchMonitor script.
* replay.log -- generated on the simulated host and copied to the monior's workspace directory when the
simulated host exits, (e.g., as the result of its configuraiton node being deleted.)  These logs are
copied whenver monitors are stopped (e.g., via the "clean" command in zkMaster).  Note however that if
the target host is hung, the replay.log file will not be copied, which can make it difficult to determine
why simulated hosts hang.


## monitor configuration file ##
The master.cfg file controls the configuraiton of the monitors,
including which events are to be monitored and the names
of selected processes. 

## Ida debug commands ##
      Reverse step over
      <shift><alt> F8 -- Run backwards to previous instruction, not backing into functions

      Reverse to modification of address
      <shift><alt> a -- Run backwards to modification of address provided in popup dialog.  Default address
      is ESP, which is overridden by either a highlighted address, or the content of a 
      highlighted register, including simple math such as "edi+1".  If the kernel modifies the address,
      the program stops at the return from the syscall.

      Reverse to modification of register
      <shift><alt> r -- Run backwards to modification of highlighted register

      Reverse
      <shift><alt> F9 -- Run backwards until a breakpoint is hit.

      Reverse to cursor
      <shift><alt> F4

      Uncall function
      <alt> F7 -- Run backwards until the invocation of the current function.

## Implementation on ZooKeeper ##
A ZooKeeper node is created for each CB, (and for each
mitigated CB).  Beneath each CB node is a set of children, one for each PoV and service poller that will be 
run with the parent CB as a sesssion.  This PoV/poller node also stores the summary log artifact for each session 
for the CB & (PoV | poller) tuple.  

## implementation details ##
Kernel text sections obtained via a script run on the target (rebuild/ksections.py), which uses the System.map and
lsmodule with the files in /sys/module/*/sections/.text.
The System.map file name must be updated in the master.cfg file whenver a new version of the CGC kernel is built.
The offset of the doDoc symbol in the player binary is copied to the monitor from the simulated target on
each target boot.
