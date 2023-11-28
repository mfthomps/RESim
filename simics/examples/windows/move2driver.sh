#!/bin/bash
# Test script for driving the Windows test machine, causing it to run the simple_server.exe
# Sends the executable, ssh keys and a "move_from_driver.sh" script to the driver.
# It then runs the move_from_driver.sh
#
fname=$RESIM_IMAGE/Windows7x64Files/Users/admin/simple_server.exe
scp -P 4022 id_rsa id_rsa.pub $fname move_from_driver.sh mike@localhost:/tmp/
ssh -p 4022 mike@localhost "cd /tmp;source ./move_from_driver.sh"
