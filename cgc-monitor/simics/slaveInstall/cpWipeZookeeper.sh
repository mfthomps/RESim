#!/bin/bash
./cpAndRun.sh wipeOutZookeeper.sh hosts_zk.txt
./cpAndRun.sh installZkShell.sh hosts.txt
./mikessh.sh putMonitorCfg hosts_mst.txt
./mikessh.sh clearDB-CB hosts_mst.txt
./mikessh.sh updateAllMasterCfgs hosts_mst.txt
