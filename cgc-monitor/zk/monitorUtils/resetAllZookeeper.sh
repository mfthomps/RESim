#!/bin/bash
#
#  Delete all zookeeper state, and recreate the initial set of required nodes
#
fab -f ./fabManage.py stop_zk_client
fab -f ./fabResetZK.py zk_reset
# give the cluster a chance to find each other
sleep 7
fab -f ./fabManage.py start_zk_client
putMonitorCfg
clearDB
