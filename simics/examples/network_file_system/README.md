# DARPA Cyber Grand Challenge (CGC) services

This directory contains files for exploring the CGC Network_File_System
service.  

The server image named in the ubuntu_driver.ini file contains
a suite of CGC services as reconstituted for Linux by Trail-of-Bits.  You can
adapt files in this directory to explore any of those services.

The driver image includes polls and proof-of-vulnerability (PoV) exploits, which can
be run from the driver using poll.py and pov.py.  Note that not all
polls and PoVs work as originally intended.  

The services run under inetd, and thus handle network IO via stdin/stdout.

The driver image includes a service.map file that maps services to their TCP ports.
And it includes a common_names.txt to map between CGC competition naming and 
the common names used for the services.

Create a RESim workspace on your Simics host and copy these files into it, e.g.,
    mkdir network_file_system
    cd network_file_system
    resim-ws.sh
    cp $RESIM_DIR/simics/examples/network_file_system/* . 
   
If you are running on NPS infrastructure, all images and the binaries named in the
ubuntu_driver.ini file should be already available through the NFS /mnt/re_images.  
Otherwise, get the disk images and binary files from 
    https://nps.box.com/s/ffuz7fgyn770xcgrdur0uf1bo1tur2gk

Untar the cgc-fs.tar.
And adjust paths in the ubuntu_driver.ini as needed.

You can then run the simulation:
    resim ubuntu_driver.ini

The driver username is mike, password is password.
You can either login via the driver console, or use:
    run-command-file mapdriver.simics
and then ssh to localhost port 4022 (assuming you've put the id_rsa key 
from RESim/simics/workspace in ~/.ssh).

## Create a snapshot for injectIO and fuzzing
Use the poll.io file to create an injectIOWatch snapshot.

The poll.io file was created using the traceFD command after selecting 
Network_File_System as the debug process and sending a poll from the driver.
The goal was to send a single data package to the server such that the data
is all injested by the kernel at once rather than a sequence of send/receives.  
Subsequent injectIO and fuzzing will overwrite the kernel buffer, and we don't 
want additional spurrious data arriving after the snapshot is created.

Use the poll.io to create a snapshot for use with fuzzing or injectIO:
    resim ubuntu_driver.ini -n
    run-command-file mapdriver.simics
    run a bit
    debugProc('Network_File_System')
    From another terminal in the workspace:
       driver-driver.py poll.directive -t
    trackIO(0, max_marks=50)
    prepInjectWatch(1, 'read0')

The max_marks option speeds up the trackIO, otherwise over 1000 data marks are generated from this input.

Update the ubuntu_driver.ini to identify read0 as the snapshot.
This snapshot can be used with the injectIO function, and with fuzzing.

## Inject a crashing input
The waa.io file was found using fuzzing (as performed latter in this README).
Restart RESim and inject that crashing input:
    resim ubuntu_driver.ini -n
    injectIO('waa.io')
Attach to the debugger using the IDA Pro plugin or the Ghidra plugin.
Use reverse data to locate the source of the corrupt address and its value.
Why is the file named "waa"?

## Fuzzing setup
To fuzz, use the poll.io file as your seed.
    mkdir -p $AFL_DATA/seeds/network_file_system
    cp poll.io $AFL_DATA/seeds/network_file_system
    clonewd.sh 2
The parameter to clonewd.sh determines how many parallel fuzzing sessions are created.
If running on a blade server other than bladet10, you can clone up to 9 copies.
Otherwise, the basic Simics licenses will let you clone 2 copies.

Then run the fuzzing session:
    runAFL ubuntu_driver.ini

After you get some crashes, quit the fuzzing session and use crashReport to
analyze the crashes:
    crashReport ubuntu_driver.ini network_file_system

Results are in /tmp/crash_reports
