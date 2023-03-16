README for CADET01 example.

The cadet01 program is a simple example of a buffer overflow.
In this example, you will use RESim to observe an exploit 
of the vulnerability and view it using IDA or Ghidra.
The example is intended to help you become familiar with RESim
and Simics.  It assumes you are already familiar with either 
IDA Pro or Ghidra.

This example requires that you put the id_rsa  and id_rsa.pub files
from simics/workspace into your local ~/.ssh directory.   This is
needed to ssh into one of the simulated computers.  Be sure to set
the mode on the id_rsa file to 400.

You should have two terminals on the system that is running Simics.
One should be in the workspace directory.  The workspace should
have been created with:
    resim-ws.sh -e 

Use the ubuntu_driver.ini configuration script to start RESim.  And
use the "-n" option to not display X11 console windows, which may slow down the system:  
   resim ubuntu_driver.ini -n

This includes a driver computer and the
target "ubuntu" system that runs the vulnerable cadet service.
The driver and the target will boot, displaying diagnostics.

When RESim presents the "simics>"  prompt, direct it to debug cadet01:
   @cgc.debugProc('cadet01')

You will have seen a message such as:
    Host TCP port 4022 -> 10.20.200.91:22
which tells you that port forwarding now lets you ssh to the driver
from your host using port 4022.

Use this ssh command from your 2nd terminal to ssh to the driver:
    ssh -p 4022 mike@localhost

If the simulation pauses while you are trying to ssh to the driver, i.e.,
it presents the "simics>" prompt, use the "c" key to continue.

Once you are on the driver, tee up the ./client.py script
and return to the Simics terminal and type "stop" to pause the simulation.
The client.py script will send data to the cadet01 service.

Save a snapshot for future runs without having to boot
   @cgc.writeConfig('cadet')

Direct RESim to watch for ROP:
   @cgc.watchROP()

Then continue the simulation (c key) and hit <enter> on the ./client.py command.

RESim will stop the simulation when it detects a ROP caused by an overwrite of an return
address from the cgc_check function (which used to return to main).

Copy the cadet01 executable to your local maching running IDA (if not the Simics server).
The executable is in simics/workspace/cadet_fs/home/mike.
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



