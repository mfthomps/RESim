README for the CGC Monitor Auomated Analysis Functions

## Introduction ##
Many of the semi-automated features of the Ida Client have been 
combined to identify the location of
interesting events in the course of exploitation of a service.
Location information is captured in the form of EIP addresses and
an instruction number derived from an execution trace of the
service.  

Interesting events include:

    * Overwrite of a return address
    * Execution of an address from the stack area
    * Return to an instruction that does not follow a call
    * Reading of protected memory in the course of a Type 2 POV
    * Transmission of protected memory values

In most cases, the event information also includes data flow
back-traces that identify instructions that move tracked data between
registers and memory.  For example, such a back-trace might illustrate
the flow of a corrupt return address value back to where it was
received via a syscall.  Back-traces of data are included for the
following:

    * Corrupted return addresses
    * Corrupt values of call registers
    * Executable payloads
    * General register values negotiated in Type 1 POVs
    * The source of protected memory addresses


## Configure and start the CGC Monitor ##
The CGC Monitor master debug configuration file must be configured with:

    trace_cb=yes
    auto_analysis=yes

Use updateAllMasterCfgs to apply the changes.

Start a CGC Monitor in a Simics workspace using 

    monitorDebug.sh auto

Alternately use tmux from the zk/monitorUtils directory 
to craete a suite of debugging monitors:

    fab -f fabMonitor startAutoTmux

## Run sessions ##
Use the "oneThrow.py" command with the "-a" option to enqueue a specific CFE session.
For example:

    oneThrow.py KPRCA_00065 34 5 7

will replay team 5's POV against team 7's defense of KPRCA\_00065 in round 34.
A specific throw number can be named using the "-s" option prior to the CSID,
and throw numbers are zero-indexed.

The results are stored in a JSON file in the /mnt/vmLib/bigstuff/auto\_analysis directory.
having a naming convention as follows:

       CSID-thrower-defender-round-throw.json

where thrower, defender, round and throw are integers representing
the team that submitted the POV, the team running the service, the
round number and the throw number within that round.  The data set contains
only one throw number per CSID/thrower/defender/round tuple.

A batch of sessions can be enqueued from a file using

    oneThrow.py auto -f path/to/file

where the named file has comma seperated values such as:

    CROMU_00046,6,2,1,58,8

Where the CSID is followed by the thrower, defender, POV type, round
and throw number (one-indexed, which is inconsitent with the oneThrow -s option).

The command will enqueue the named sessions *unless there already exists a 
corresponding json file in the /mnt/vmLib/bigstuff/auto_analysis directory.

Use the "clearClient" command to remove all previously enqueued sessions.
