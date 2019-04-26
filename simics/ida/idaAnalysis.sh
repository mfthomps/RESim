#!/bin/bash
echo starting Ida for $1  directory is $2
#echo /home/mike/ida-6.4/idaq -B -c -o$2/ida/my.idb $1
echo /home/mike/ida-6.8/idaq -T"CGC" -B $1
/home/mike/ida-6.8/idaq -T"CGC" -B $1
