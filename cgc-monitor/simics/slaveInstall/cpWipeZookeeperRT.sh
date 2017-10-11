#!/bin/bash
./cpAndRun.sh wipeOutZookeeper.sh hosts_zk_rbt.txt
./cpAndRun.sh installZkShell.sh hosts_rbt.txt
./mikessh.sh putMonitorCfg hosts_mst_rbt.txt
./mikessh.sh clearDB-CB hosts_mst_rbt.txt
./mikessh.sh updateAllMasterCfgs hosts_mst_rbt.txt
