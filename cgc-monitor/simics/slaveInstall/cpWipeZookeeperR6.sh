#!/bin/bash
./cpAndRun.sh wipeOutZookeeper.sh hosts_zk_rb6.txt
./cpAndRun.sh installZkShell.sh hosts_rb6.txt
./mikessh.sh putMonitorCfg hosts_mst_rb6.txt
./mikessh.sh clearDB-CB hosts_mst_rb6.txt
./mikessh.sh updateAllMasterCfgs hosts_mst_rb6.txt
