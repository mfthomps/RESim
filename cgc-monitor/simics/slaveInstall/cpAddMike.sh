#!/bin/bash
# copy the script to add user mike to the remote host, and then execute it
# user created with no password, access via ssh keys
pscp -h hosts.txt -l testuser -A -O StrictHostKeyChecking=no addMike.sh /tmp/addMike.sh
./dopssh.sh "chmod a+x /tmp/addMike.sh"
./dopssh.sh "/tmp/addMike.sh"

