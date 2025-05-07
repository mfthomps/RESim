#!/bin/bash
#
# Watch AFL and kill it when specified period elapses
# without finding a new path.
#
if [ "$#" -ne 2 ]; then
    echo "Kill afl after N seconds elapse without finding a new path"
    echo "Usage: fuzz_watchdog.sh target timeout"
    exit
fi
target=$1
timeout=$2
log=/tmp/watchdog.log
rm -f $log
echo "fuzz_watchdog.sh begin" >> $log

while [ 1 ]; do
    running=$(ps aux | grep '[a]fl-fuzz' | awk '{print $2}')
    if [ ! -z "$running" ]; then
        echo "AFL not running, begin" >> $log
        break
    else
        sleep 10
    fi
done
while [ 1 ]; do
    running=$(ps aux | grep '[a]fl-fuzz' | awk '{print $2}')
    if [ -z "$running" ]; then
        echo "AFL not running, bail" >> $log
        exit
    fi
    result=$(fuzz-summary.py $target | grep "Most recent" | awk '{ print $5 }')
    echo "result is $result" >> $log
    if [ ! -z "$result" ] && [ $result -gt $timeout ]; then
        echo "is greater" >> $log
        rm -f .watchdog_run
        kill-afl.sh
        break
    else
        if [ ! -f .watchdog_run ]; then
            echo ".watchdog_run not found, bail" >> $log
            break
        fi
        echo "not greater, sleep" >> $log
        sleep 10
    fi
done
