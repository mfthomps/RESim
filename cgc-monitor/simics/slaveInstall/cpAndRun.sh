#!/bin/bash
# copy the script to add user cgc to the remote host, and then execute it
# user created with no password, access via ssh keys
HOSTS=hosts.txt
if [ ! -z "$2" ]; then
   HOSTS=$2
fi 
pscp -h $HOSTS -l mike $1 /tmp/$1
./mikessh.sh "chmod a+x /tmp/$1" $HOSTS
echo "command will be: /tmp/$12"
./mikessh.sh "/tmp/$1" $HOSTS

