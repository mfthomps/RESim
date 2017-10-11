#!/bin/bash
# Intended to be run after a slave has had a generic linux installed
# This is the first step.  After a reboot, run doSlaveScripts.sh
./cpAddMike.sh
./mikeKeys.sh
./cpAddCGC.sh
./cgcKeys.sh
./cpInstallBuildUtils.sh
./fixNetwork.sh
