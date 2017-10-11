#!/bin/bash
# Use Simics TFTP server (on simulated network node) to put files
# to the host upon which this simulated target is running
# putTFTP.sh file
here=`pwd`
echo "connect 10.10.0.1" >cmd.txt
echo "bin">>cmd.txt
echo "put $1">>cmd.txt
echo "quit">>cmd.txt
tftp < cmd.txt
cd $here
