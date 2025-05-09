# RESim
## Reverse engineering using a full system simulator.

* Dynamic analysis by instrumenting simulated hardware using Simics[1]
* Trace process trees, system calls and individual programs
* Reverse execution to selected breakpoints and events
* Integrated with IDA Pro(tm) debugging client
* Ghidra plugins for use with the Ghidra debugger
* Fuzz with a customized AFL, injecting directly into simulated memory

RESim is a dynamic system analysis tool that provides detailed insight into processes, programs and data flow within networked computers.  RESim simulates networks of computers through use of the Simics 
platform’s high fidelity models of processors, peripheral devices (e.g., network interface cards), and disks.  The networked computer platform models load and run targeted software copied from images extracted from the physical systems being simulated.

RESim aids reverse engineering and vulnerability analysis of networks of Linux-based and Windows systems by inventorying processes in terms of the programs they execute and the data they consume.  Data sources include files, device interfaces and inter-process communication mechanisms.   Process execution and data consumption is documented through dynamic analysis of a running simulated system without installation or injection of software into the simulated system, and without detailed knowledge of the kernel hosting the processes.

RESim also provides interactive visibility into individual executing programs through use 
plug-ins to the IDA Pro and Ghidra disassembler/debuggers.  The disassembler/debugger
allows setting breakpoints to pause the simulation at selected events in either future time, or past time[2].  For 
example, RESim can direct the simulation state to reverse until the most recent modification of a selected memory address.   
Reloadable checkpoints may be generated at any point during system execution.  
A RESim simulation can be paused for inspection, e.g., when a specified process is scheduled for execution, and subsequently continued, potentially with altered memory or register state.  The analyst can explicitly modify memory or register content, and can also dynamically augment memory 
based on system events, e.g., change a password file entry when read by the *su* program.

Analysis is performed entirely through observation of the simulated target system’s memory and processor state, 
without need for shells, software injection, or kernel symbol tables.   The analysis is said to be *external* because the observation functions have no effect on the state of the simulated system.

RESim has been integrated with the *American Fuzzing Lop* (AFL) fuzzer.  This fuzzing system injects fuzzed data directly into the
application read buffer, simplifying the fuzzing setup and workflow.  RESim automatically replays and analyzes any detected crashes, 
identifying the causes of crashes, e.g., corruption of execution control.

Please refer to [the RESim User's Guide](docs/RESim-UsersGuide.pdf) for additional information.  A brief demonstration of RESim can be seen here:
(https://nps.box.com/s/rf3n104ualg38pon6b7fm6m6wqk9zz50)

Example disk images are described in this [readme](simics/examples/network\_file\_system/README.md) 

RESim is derived from a software vetting and forensic analysis platform created for the DARPA Cyber Grand Challenge.  That repo is here:
https://github.com/mfthomps/cgc-monitor.  A paper describing that work is at https://www.sciencedirect.com/science/article/pii/S1742287618301920
And a fine summary of the use of Simics in the CGC Monitor is at https://software.intel.com/content/www/us/en/develop/blogs/simics-software-automates-cyber-grand-challenge-validation.html

[1]Simics is a full system simulator developed by Intel, which holds all relevant trademarks.
[2]Simics 7 deprecated "reverse execution", be RESim adds it back.
## License
```
This software was created by United States Government employees
and may not be copyrighted.
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```
