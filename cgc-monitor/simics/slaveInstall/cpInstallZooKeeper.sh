#!/bin/bash
# Install zookeeper on the current set of hosts named in hosts.txt
pscp -h hosts.txt -l mike ../masterInstall/installZooKeeper.sh /tmp/installZooKeeper.sh
pscp -h hosts.txt -l mike nfsMount.sh /tmp/nfsMount.sh
./mikessh.sh /tmp/nfsMount.sh
./cpZkHosts.sh
./cpSlaveBootstrap.sh
./mikessh.sh /tmp/installZooKeeper.sh
