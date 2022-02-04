#!/bin/bash
if [ ! -f drones.txt ]; then
   echo "No drones.txt file found"
   exit
fi
if [ "$#" -ne 1 ]; then
    echo "get-tars.sh <delay>"
    echo "   Sync the tars, delaying the given number of minutes between them"
    exit
fi
timeout=$1
flist=$(cat drones.txt)
flist=$flist" "$HOSTNAME
here=$(pwd)
base=$(basename $here)
aflout=$AFL_DATA/output/$base
echo "Starting get-tars.sh"
while [ ! -f /tmp/resimdie.txt ]; do 
    for f in $flist; do
        echo "Get sync dir from $f"
        ssh $USER@$f -o StrictHostKeyChecking=no bash -c "cd .;cd $aflout && tar -czf - $f_resim*/[qf]*" >host_$f.tgz
    done
    for s in $flist; do
        for d in $flist; do
            test "$s" = "$d" && continue
            ssh $USER@$d -o StrictHostKeyChecking=no bash -c "cd .;cd $aflout && tar --skip-old-files -xzf -" <host_$s.tgz
        done
    done
    sleep "$timeout"m
done

echo "Exiting get-tars.sh"
