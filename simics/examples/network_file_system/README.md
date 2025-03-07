# DARPA Cyber Grand Challenge (CGC) services

This directory contains files for exploring the CGC Network\_File\_System
service.  

The server image named in the ubuntu\_driver.ini file contains
a suite of CGC services as reconstituted for Linux by Trail-of-Bits.  You can
adapt files in this directory to explore any of those services.

The driver image includes polls and proof-of-vulnerability (PoV) exploits, which can
be run from the driver using poll.py and pov.py.  Note that not all
polls and PoVs work as originally intended.  

The services run under inetd, and thus handle network IO via stdin/stdout.

The driver image includes a service.map file that maps services to their TCP ports.
And it includes a common\_names.txt to map between CGC competition naming and 
the common names used for the services.

Create a RESim workspace on your Simics host and copy these files into it, e.g.,

      mkdir network_file_system
      cd network_file_system
      resim-ws.sh
      cp $RESIM_DIR/simics/examples/network_file_system/* . 
   
If you are running on NPS infrastructure, all images and the binaries named in the
ubuntu\_driver.ini file should be already available through the RESIM\_IMAGE
environment variable.

Otherwise, get the disk images and binary files from 
    https://nps.box.com/s/ffuz7fgyn770xcgrdur0uf1bo1tur2gk
and untar the cgc-fs.tar.
And adjust paths in the ubuntu\_driver.ini as needed.

You can then run the simulation:

      resim ubuntu_driver.ini

It may take a few moments for the driver and target system to boot.
The simulation will stop at the simics> prompt when it is booted.
Use the "c" command at the simics prompt to run forward a while to get
past all the Linux initialization.  Use the "ptime" command to watch time
advance.  Use the "stop" stop command to stop the simuation when "Time"
seems to be advancing close to or faster than real time.

Create a snapshot so you can return to that point without rebooting:
    @cgc.writeConfig('running')

The driver username is mike, password is password.
You can either login via the driver console, or use:
       run-command-file mapdriver.simics
and then ssh to localhost port 4022 (assuming you've put the id\_rsa key 
from RESim/simics/workspace in ~/.ssh).

## Create a snapshot for injectIO and fuzzing
Use the poll.io file to create an prepInjectWatch snapshot.

The poll.io file was created using the traceFD command after selecting 
Network\_File\_System as the debug process and sending a poll from the driver.
That file is named tpoll.io
A lot of Z characters were then appended to that file as a file named 
poll.io.  (As noted below, the Z character is used to find the length of kernel buffers.)
The goal is to send a single data package to the server such that the data
is all injested by the kernel at once rather than a sequence of send/receives.  
Subsequent injectIO and fuzzing will overwrite the kernel buffer, and we don't 
want additional spurrious data arriving after the snapshot is created.

Use the poll.io to create a snapshot for use with fuzzing or injectIO:
    Start from the "running" snapshot you created above.
    resim ubuntu_driver.ini -n
    run-command-file mapdriver.simics
    @cgc.debugProc('Network_File_System')
    From another terminal in the workspace:
      drive-driver.py poll.directive -t -d
    @cgc.writeConfig('network_file_system')
    @cgc.trackIO(0, max_marks=50, kbuf=True)
    @cgc.prepInjectWatch(1, 'read0')

The max\_marks option speeds up the trackIO, otherwise over 1000 data marks are generated from this input.
The kbuf option tells the trackIO function to look for kernel buffer addresses.

Update the ubuntu\_driver.ini to identify read0 as the snapshot.
This snapshot can be used with the injectIO function, and with fuzzing.

## Inject a crashing input
The waa.io file was found using fuzzing (as performed latter in this README).
Restart RESim and inject that crashing input:

     resim ubuntu_driver.ini -n
     @cgc.injectIO('waa.io')
   
Attach to the debugger using the IDA Pro plugin or the Ghidra plugin.
Use reverse data to locate the source of the corrupt address and its value.

## Fuzzing setup
To fuzz, use the poll.io file as your seed.

     mkdir -p $AFL_DATA/seeds/network_file_system
     cp tpoll.io $AFL_DATA/seeds/network_file_system
     clonewd.sh 2 (skip this step if you are only able to run a single instance of Simics).
   
The parameter to clonewd.sh determines how many parallel fuzzing sessions are created.
If running on a blade server other than bladet10, you can clone up to 9 copies.
Otherwise, the basic Simics licenses will let you clone 2 copies (or not, depending on the
Simics version and license files).

Then run the fuzzing session:

     runAFL ubuntu_driver.ini

If you are limited to a single Simics instance, use the "--dirty" option to runAFL
to cause AFL to skip its deterministic mode.

You will notice that the fuzzer runs extremely slow compared to many other environments.
Indeed, fuzzing on a more typical platform would make sense for the types of services 
represented by the CGC corpus.  The fuzzing provided by RESim is intended for systems that
are more complex than these simple services, and are consequentially difficult to harness.
If crashing inputs are found on a different fuzzing platform, it is often useful to bring
those inputs to a RESim platform in order to analyze the root cause of the crash,
e.g., using reverse execution and data tracking features.

AFL should find the first crash in about ten to twenty minutes, depending on the
number of Simics instances.
 
After you get some crashes, quit the fuzzing session and use crashReport to
analyze the crashes:

     crashReport ubuntu_driver.ini network_file_system

Results are in /tmp/crash\_reports
