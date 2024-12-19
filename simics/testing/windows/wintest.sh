#!/bin/bash
#
# Regression test for windows 7 RESim functions
# Run this from the parent of what will be the test directory.
# The script first deletes, then creates a test directory called "windows_test"
# It uses files from simics/examples/windows, and the craff file named in that
# wintest.ini file
#
rm -fr windows_test
mkdir windows_test
cd windows_test
resim-ws.sh
cp $RESIM_DIR/simics/examples/windows/* .
chmod 400 id_rsa
cp $RESIM_DIR/simics/testing/windows/* .

$HOME/bin/set-title "wintest"
echo "run-python-file run-to-boot.py" | resim wintest.ini -n || exit
sed -i '/RESIM_TARGET/a RUN_FROM_SNAP=booted_test' wintest.ini
sed -i '/BOOT_CHUNKS/a ONLY_PROGS=simple.only_prog' wintest.ini
echo "@gkp.go()" | resim wintest.ini -n || exit
resim wintest.ini -e "@gkp.go(quit=True)" || exit
sed -i 's/^CREATE_RESIM_PARAMS=YES/#CREATE_RESIM_PARAMS=YES/' wintest.ini
resim wintest.ini -c save_running.simics || exit
sed -i 's/RUN_FROM_SNAP=booted_test/RUN_FROM_SNAP=running_test/' wintest.ini
resim wintest.ini -c trace_test.simics
./check_trace.sh || exit
resim wintest.ini -c accept_test.simics
./check_accept.sh || exit
sed -i 's/RUN_FROM_SNAP=running_test/RUN_FROM_SNAP=accept_test/' wintest.ini
resim wintest.ini -c track_test.simics
./check_track.sh || exit
