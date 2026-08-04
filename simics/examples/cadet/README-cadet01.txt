README for CADET01 example.

The cadet01 program is a simple example of a buffer overflow.
In this example, you will use RESim to observe analyze the
program and observe an exploit of the vulnerability.  You will
also be able to analyze the program using IDA or Ghidra.  
The example is intended to help you become familiar with RESim
and Simics.  It assumes you are already familiar with either 
IDA Pro or Ghidra.

This example requires that you put the id_rsa file
from simics/workspace into your local ~/.ssh directory.   This is
needed to ssh into one of the simulated computers.  Be sure to set
the mode on the id_rsa file to 400.

The example requires two disk images located relative to your $RESIM_IMAGES directory.  
If you are not running on the NPS RESim VLAN and do not otherwise have these images
in your $RESIM_IMAGES directory, then get them as described below. 

    The target cadet image from:
       https://nps01-my.sharepoint.com/:u:/g/personal/mfthomps_nps_edu/IQC-hSPskpwKRqvVSauYb_l4AU6FLcnA4awKbLYIQL5Pn18?e=9gzkHU

    should be copied to:
        $RESIM_IMAGES/cadet01/cadet.disk0.hd_image.craff

    And, if not already done, the driver image at
       https://nps01-my.sharepoint.com/:u:/g/personal/mfthomps_nps_edu/IQCV_MiNKTuQULQgny7z3A0RAc51gxYUK3ZwbxZvwhvPJiA?e=HRZgYw
    should be copied to:
        $RESIM_IMAGES/driver/driver_22.disk0.hd_image.craff

You should have at least two terminals currently in the cadet workspace
directory on the system that is running Simics.  If you do not yet have a
cadet workspace, use:
    mkdir cadet
    cd cadet
    resim-ws.sh -e 
The -e causes the cadet example files to be copied into your workspace. Otherwise the command
has not options.

Use the cadet_driver.ini configuration file to start RESim.  And
use the "-n" option supress display of console windows, which may significantly slow down the system:  
   resim cadet_driver.ini -n

The resulting simulation configuration includes a driver computer and the
target "cadet" system that runs the vulnerable cadet service.
The driver and the cadet target will boot, displaying diagnostics.

You will see the "simics>" prompt when the cadet target has booted enough to give
RESim insight into its state.  At this point the simulation is paused and you can issue
RESim commands (e.g., @cgc.tasks()) and Simics commands (e.g., list-components -v)

Direct RESim to debug the cadet01 process:
   @cgc.debugProc('cadet01', track_threads=False)
The track_threads option is an optimization that tells RESim to not gather information 
about other processes being created while we wait for cadet01 to start.

When The simics> prompt appears, you will see some diagnostics indicating that cadet01 is
started and we are set to analyze it.  Create a snapshot so you can return to this
state in the future:

    @cgc.writeConfig('cadet')

We will start our analysis by generating a system call trace:
    @cgc.traceAll()
    c
Let it run for a few seconds and then quit.  Then look at the logs/syscall_trace-cadet...txt
file.  Notice that cadet01 binds to TCP port 5001.  We can now use that port number to send data
to cadet01.  HOWEVER, even though cadet01 has started at our snapshot named caded, the target computer 
is still in the process of initializing, with many processes being created.  If we try to debug now, 
the system will be slow, bogged down as initialization completes.  This is a common situation and 
you are best served by running the simulation forward until things settle out.  

Alter your cadet_driver.ini to include
   RUN_FROM_SNAP=cadet
and start the simulation.  Then run forward until 40 seconds of real time have passed:
    @cgc.runToSeconds(40)
Now with the simics> prompt appears, things should not be quite so busy.
Save a snapshot so you can return to this state in the future:
    @cgc.writeConfig('cadet40')

We will now send data to the cadet01 program to watch what it does, in terms of the
system calls it makes.  We typically send data to a target via the driver computer
using the drive-driver utility.  In your 2nd terminal that is in the cadet directory,
view the pal.directive file, and the pal.io file it refers to.  
While the system is paused at that cadet40 snapshot, use:
    drive-driver pal.directive
which will send the pal.io to the driver along with instructions to send the data in that
file to port 5001 of the target (but only after the simulation is unpaused).  

Back at the simics> prompt, use:
    @cgc.debugSnap()
to tell RESim you wish to analyze the process you were analyzing when the snapshot was made.
That command will unpause the simulation and will run until cadet01 is scheduled.  Note the diagnostics
in your driver terminal reflect sending of data to the driver.

It may take a moment for the simics> prompt to return, indicating that cadet01 is scheduled, i.e.,
has returned from the "accept" system call you saw in the earlier trace.  Generate a new system
call trace:
    @cgc.traceAll()
and let it run for a few seconds.  Then review the logs/syscall_trace-cadet...txt file.

Next you will observe the effects of a crashing input.  Restart RESim from the same cadet40
snapshot, but this time send:
    drive-driver crash.directive
Use @cgc.debugSnap() again and this time just press "c" to continue after the simics> 
prompt is returned.  RESim should report a SEGV, and display the faulting instruction.
Use the Simics
    pregs
command to view register content.  Notice how the value of eax, whose value is dereferenced,
looks suspicious.  Trace the source of the value in eax using:
   @cgc.revTaintReg('eax')
When it completes and the simics> prompt returns, use 
   @cgc.listBookmarks()
to view execution points that affected the value of eax.  The list is in time order.
Note the first "backtrack" entry in the list reflects the kernel reading in a value
into an address from a read system call, as reflected in the recent call trace.

Restart from cadet40, but this time send "rop.directive" and type:
    @cgc.watchROP()
before pressing "c" to continue.  RESim will stop the simulation when it detects 
a ROP caused by an overwrite of an return address from the cgc_check function 
(which used to return to main).

Start IDA using the runIDA.sh script. The first time you run IDA for a target binary,
use the dumpFuns.py and findBlocks.py scripts to generate database files used by RESim for
the target (File / script files; or View / recent scripts).  Use shift R to attach to 
the process and load the RESim plugins.  Alternately, you may use our fork of the Ghidra
disassembler debugger as described in the RESim User Guide.

View the stack and observe the return address is to somewhere within the cgc_check function.

Use the IDA "Debugger / RESim / backtrack / ^Wrote to SP" function back-trace content of stack.  
Note IDA the output window (and the Bookmarks window) identifies the address of the
bytes written by kernel during receive operation.  Use "stack trace" window to view call frames.  
Click once in the "IDA View-EIP" window to set your context, and then double click
the call to cgc_receive_delim in the stack trace window. Then right click, RESim / reverse to cursor.  

Note the return pointer was written at offset 92 into the buffer address stored at (esp+4).    
And esp+8 is the max count (128).  Then in the function preface,
observe the buffer is only 0x40 (0x58-0x18) (64)bytes.  The vars will get trashed during any overflow, so the
content of the buffer matters.

Since you reversed to the call to cgc_receive_delim, the data is not yet in the buffer.  Click in the
Hex View-1 window, press "g" and provide the address of the buffer.  Use f8 to
step over the call, and observe the new content of the buffer.

A notional view of the stack (aslr will vary it):

Low memory


   bfdd05fc   080489e1     ret to cgc_check from cgc_receive_delim


   bfdd0610   rec buffer


   bfdd066c    08048912    ret to main from cgc_check


High memory



