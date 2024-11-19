#!/bin/bash
sed -i 's/.RUN_FROM_SNAP.*$/RUN_FROM_SNAP=odhcpd/' fvp.ini
sed -i 's/start_openwrt.simics/test_debug.simics/' fvp.ini
resim fvp.ini -n
line=$(grep "cpu.name is fvp.cluster.0." logs/monitors/resim.log)
if [ -z "$line" ]; then
    echo "test_debug failed to find show line"
    exit 1
else
    uhttpd=$(echo $line | grep uhttpd)
    if [ -z "$uhttpd" ]; then
        echo "test_debug failed to find uhttpd in show"
        echo $line
        exit 1
    else
        echo "test debug passed"
    fi
fi
