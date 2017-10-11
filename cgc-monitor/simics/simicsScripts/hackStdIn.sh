#!/bin/bash
#
# open a pipe used by a simics debug instance
# and leave it open
#
function clean_up {
    print "hackStdIn exiting from trap"
    echo q >> simics.stdin
    exit
}
trap clean_up SIGHUP SIGINT SIGTERM
exec 3> simics.stdin
while true
do
    sleep 3
done 

