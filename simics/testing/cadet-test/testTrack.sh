#!/bin/bash
$HOME/bin/set-title "cadet01-tst"
rm -fr cadetread
sed -i '/INIT_SCRIPT/d' ubuntu_driver.ini
sed -i '/INTERACT_SCRIPT/d' ubuntu_driver.ini
sed -i '/RESIM_TARGET/a RUN_FROM_SNAP=cadet' ubuntu_driver.ini
./doprep.sh &
resim ubuntu_driver.ini -n
./checkPrep.sh || exit 1
echo "not a pal" > dumb.io
sed -i 's/RUN_FROM_SNAP=cadet/RUN_FROM_SNAP=cadetread/' ubuntu_driver.ini
./dotrack.sh &
resim ubuntu_driver.ini -n
./checkTrack.sh || exit 1
