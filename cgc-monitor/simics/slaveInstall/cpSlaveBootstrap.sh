#!/bin/bash
# copy the monitorSlaveBootstrap.sh script and extact it
pscp -h hosts.txt -l mike monitorSlaveBootstrap.sh /mnt/cgc/monitorSlaveBootstrap.sh
pscp -h hosts.txt -l mike /mnt/vmLib$1/cgcForensicsRepo/monitor.tar /tmp/monitor.tar
echo "copying monitor tar from vmLib$1"
./mikessh.sh "tar -xvf /tmp/monitor.tar -C /mnt/cgc"
