#!/bin/bash
sed -i '/RUN_FROM_SNAP/d' ubuntu_driver.ini
./testTrack.sh
