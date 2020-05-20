# RESim
## Reverse engineering using a full system simulator.

RESim is a dynamic system analysis tool that provides detailed insight into processes, programs and data flow within networked computers.  RESim simulates networks of computers through use of the Simics'[1] 
platform’s high fidelity models of processors, peripheral devices (e.g., network interface cards), and disks.  The networked simulated computers load and run targeted software copied from disk images extracted from the physical systems being modeled.

Broadly, RESim aids reverse engineering of networks of Linux-based systems by inventorying processes in terms of the programs they execute and the data they consume.  Data sources include files, device interfaces and inter-process communication mechanisms.   Process execution and data consumption is documented through dynamic analysis of a running simulated system without installation or injection of software into the simulated system, and without detailed knowledge of kernel hosting the processes.

RESim also provides interactive visibility into individual executing programs through use of a 
custom plug-in to the IDA Pro disassembler/debugger.  The disassembler/debugger
allows setting breakpoints to pause the simulation at selected events in either future time, or past time.  For 
example, RESim can direct the simulation state to reverse until the most recent modification of a selected memory address.   
Reloadable checkpoints may be generated at any point during system execution.  
A RESim simulation can be paused for inspection, e.g., when a specified process is scheduled for execution, and subsequently continued, potentially with altered memory or register state.  The analyst can explicitly modify memory or register content, and can also dynamically augment memory 
based on system events, e.g., change a password file entry when read by the *su* program.

Analysis is performed entirely through observation of the simulated target system’s memory and processor state, 
without need for shells, software injection, or kernel symbol tables.   The analysis is said to be *external* because the analysis observation functions have no effect on the state of the simulated system.

Please refer to [the RESim User's Guide](docs/RESim-UsersGuide.pdf) for additional information.  A brief demonstration of RESim can be seen here:
(https://nps.box.com/s/rf3n104ualg38pon6b7fm6m6wqk9zz50)

RESim is based on a software vetting and forensic analysis platform created for the DARPA Cyber Grand Challenge.  That repo is here:
https://github.com/mfthomps/cgc-monitor.  A paper describing that work is at https://www.sciencedirect.com/science/article/pii/S1742287618301920
And a fine summary of the use of Simics in the CGC Monitor is at https://software.intel.com/content/www/us/en/develop/blogs/simics-software-automates-cyber-grand-challenge-validation.html

[1]Simics is a full system simulator sold by Intel/Wind River, which holds all relevant trademarks.
