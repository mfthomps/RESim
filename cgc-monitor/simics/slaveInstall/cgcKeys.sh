#!/bin/bash
# copy authorized keys to the remote system and install them for user cgc
pscp -h hosts.txt -l mike cgc_authorized_keys /tmp/cgc_authorized_keys
./mikessh.sh "sudo cp /tmp/cgc_authorized_keys /home/cgc/.ssh/authorized_keys"
./mikessh.sh "sudo chown cgc:cgc /home/cgc/.ssh/authorized_keys"
