#!/bin/bash
#
# Automated test of RESim arm64 using the openwrt system
#
# Create workspace and populate it with openwrt RESim files and test scripts
rm -fr openwrt-test
mkdir openwrt-test
cd openwrt-test
resim-ws.sh
cp $RESIM_DIR/simics/examples/openwrt/fvp.param .
cp $RESIM_DIR/simics/testing/openwrt/* .
# Set the init script to run until the odhcpd starts
resim fvp.ini -c start_openwrt.simics
# Test debug of uhttpd
./test_debug.sh
./test_track.sh
