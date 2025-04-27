#!/bin/bash
snap=$1
sed "s/^RUN_FROM_SNAP.*$/RUN_FROM_SNAP=$snap/" ecdis.ini > tmp.ini
