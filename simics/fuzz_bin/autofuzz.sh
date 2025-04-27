#!/bin/bash

if [ "$#" -ne 3 ]; then
    echo "autofuzz.sh ws_name program fuzz_timeout"
    echo "   Run afl within the given auto workspace (auto_ws/ws_name)"
    exit
fi
ws_name=$1
program=$2
fuzz_timeout=$3
echo "create watchdog"
fuzz_watchdog.sh $ws_name $fuzz_timeout &
cd auto_ws/$ws_name
echo "start runAFL"
runAFL tmp.ini -b
echo "runAFL done, remove .watchdog_run"
rm -f ../../.watchdog_run
echo "runPlay"
runPlay tmp.ini $program
echo "runPlay done"
dedupCoverage.py tmp.ini $ws_name
