#!/bin/bash
# copy authorized keys to the remote system and install them for user mike
pscp -h hosts.txt -l testuser -A mike_authorized_keys /tmp/authorized_keys
./dopssh.sh "sudo cp /tmp/authorized_keys /home/mike/.ssh/authorized_keys"
./dopssh.sh "sudo chown mike:mike /home/mike/.ssh/authorized_keys"
