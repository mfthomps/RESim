#!/bin/bash
hitfile=$RESIM_IDA_DATA/cadet_fs/cadet01/cadet01.cadet-tst.hits
rm -f $hitfile
runPlay ubuntu_driver.ini cadet01
if [ -f $hitfile ]; then
    gotit=$( grep 134514820 $hitfile )
    if [ -z "$gotit" ]; then
        echo "runPlay failed to find value in $hitfile"
        exit 1
    else
        echo "runPlay passed"
    fi 
else
    echo "runPlay failed to create file at $hitfile"
    exit 1
fi
