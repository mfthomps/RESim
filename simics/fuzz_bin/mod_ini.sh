#!/bin/bash
ini=$1
snap=$2
sed "s/^RUN_FROM_SNAP.*$/RUN_FROM_SNAP=$snap/" $ini > tmp.ini.working
mv tmp.ini.working tmp.ini
