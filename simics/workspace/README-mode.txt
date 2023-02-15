README for modetest.py

This is an example Simics python script that does not use RESim.  It illustrates the use of a few types of
Simics HAPs.  The mode hap is used within RESim's getKernelParameters function to find kernel entry points.
The modetest.py script is an example of how that is done. And this README walks you through several Simics
operations.  It is intended to introduce users to Simics scripting to get a feel for how RESim works.

The instructions below assume you start simics with the "-no-gui" switch, e.g., to prevent the extremely
slow X11 exchanges for Simics consoles.

The run-one.simics will create a single x86 computer that has a boot disk image containing 64 bit Linux:

    simics> run-command-file run-one.simics

The above loads the model of the computer without starting it.  You would then use "c" to continue and watch diagnostics spew.
At some point you'll see:
   <board0.serconsole.con>cl-qsp login: simics\r\r\n

That is a clue that the target is booted.

At that point, you could create a snapshot:
    write-configuration running

Now that you have a snapshot, you can quit simics (q) and restart
simics loading the snapshot:
    ./simics -no-gui running

Use "pregs" to see the register values.
Since this is 64-bit Linux, kernel addresses all start with 0xff...
and user addresses top-out at 0x00007fff..

Use "x" to examine memory, e.g. to look at the content of the stack,
   x %rsp

Use can also use absolute addresses (prefix with 0x)

The modetest.py script can then be run:
    run-python-script modetest.py
That will set the hap.  Then continue a few times and observe the output.

The modetest.py defines an object "mt" as being an instance of our ModeTest class.
you would then name that object from the simics command line using "@mt", e.g.,
    @mt.rmHap()
to remove the hap.

Use "enable-reverse-execution" to enable recording to let you "run backwards".
Run forward a few times with the hap set until you see you are entering supervisor state.
Then remove the hap.  And then step backwards:
   rev 1

or forwards
   si

Note the assembly instruction on kernel entry.  If it is "syscall", then you know you are entering
the kernel with a syscall.

Note the value of rip printed by the modeChanged function is not the same as what you see
with pregs.  That is becuase at the instant of the mode changed, the instruction has not completed.
By the time the SIM_break_simulation completes, the instrution has completed and you'll be 
in the kernel (assuming you are coming in).

Experiment with the @mt.setBreak function.  Try finding the syscall entry point 
and setting a breakpoint/hap on it.
