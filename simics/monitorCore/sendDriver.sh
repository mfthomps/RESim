#!/bin/bash
#
# Copy a client and a file for that client to send to a target.
# The files are copied to a driver whose ssh port is mapped to
# localhost 4022 via Simics real networks and port forwarding.
# Assumes the driver has a user "mike", and ssh keys are used
#
fname=/tmp/sendudp
#
# Catch failures that likely can't occur in this context
#
i="0"
while !  scp -P 4022 $fname mike@localhost:/tmp/sendudp
do
    sleep 1
    i=$[$i+1]
    if [ $i -gt 10 ];then
        exit
    fi
done
scp -P 4022 $1 mike@localhost:/tmp/
base=$(basename -- $1)
ssh -p 4022 mike@localhost chmod a+x /tmp/$base
echo "now run it"
ssh -p 4022 mike@localhost /tmp/$base $2 $3 $4
echo "back from run"
