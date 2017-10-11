#!/bin/bash
# copy the zookeeper hosts file to targets
pscp -h hosts.txt -l mike zk_hosts.txt /mnt/cgc/zk_hosts.txt

