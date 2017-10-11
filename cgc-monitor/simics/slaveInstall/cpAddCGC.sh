#!/bin/bash
# copy the script to add user cgc to the remote host, and then execute it
# user created with no password, access via ssh keys
pscp -h hosts.txt -l mike addCGC.sh /tmp/addCGC.sh
./mikessh.sh "chmod a+x /tmp/addCGC.sh"
./mikessh.sh "/tmp/addCGC.sh"

