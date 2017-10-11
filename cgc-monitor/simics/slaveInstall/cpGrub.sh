#!/bin/bash
# copy the script to add user cgc to the remote host, and then execute it
# user created with no password, access via ssh keys
pscp -h hosts.txt -l mike grub /tmp/grub
./mikessh.sh "sudo cp /tmp/grub /etc/default/grub"
./mikessh.sh "sudo update-grub"

