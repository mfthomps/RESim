#!/bin/bash
# run a ssh script as mike
HOSTS=hosts.txt
if [ ! -z "$2" ]; then
   HOSTS=$2
fi 
pssh -h $HOSTS -l mike -t 0 --outdir /tmp/sshout -x "-o StrictHostKeyChecking=no" $1 
