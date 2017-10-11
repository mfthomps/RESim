#!/bin/bash
#
#  Wipe out an entire zookeeper data file, all-nodes-go-bye
#
sudo /etc/init.d/zookeeperService stop
sudo rm -fr /media/sdb1/zk/version*
sudo /etc/init.d/zookeeperService start
