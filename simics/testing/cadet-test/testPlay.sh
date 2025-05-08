#!/bin/bash
hitfile=$RESIM_IDA_DATA/cadet01/cadet_fs/home/mike/cadet01.cadet-tst.hits
rm -f $hitfile
echo "testPlay begin"
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
