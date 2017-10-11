#!/bin/bash
#
#  Mount a nfs volume on /mnt/vmLib unless such a volume is already mounted
#
exec 1<&-
exec 2<&-
exec 1<>/tmp/nfsMount.log
exec 2>&1
host=$1
if [ -z "$1" ]; then
    host=installrepo
fi
echo "will try to mount on " $host
DEVEL=$(grep 'vmLib' /etc/fstab)
if [ $? -eq 0 ]; then
    echo "must be devel machine, vmLib in fstab, do not mount"
    exit
fi
DEVEL=$(ls /mnt/vmLib/bigstuff)
if [ $? -eq 0 ]; then
    echo "must be the repo do not mount"
    exit
fi

VOL=$(df | grep 'vmLib')
if [ $? -eq 0 ]; then
        echo "mountVmLib already mounted "
else
        sudo mount -t nfs $host:/mnt/vmLib /mnt/vmLib
fi

