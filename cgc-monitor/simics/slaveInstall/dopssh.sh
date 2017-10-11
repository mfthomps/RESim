#!/bin/bash
# run ssh command as testuser, assumes user needs a password
pssh -h hosts.txt -l testuser -A -x "-o StrictHostKeyChecking=no" $1
