#!/bin/bash
pscp -h hosts.txt -l mike updateSimics.sh /tmp/updateSimics.sh
pscp -h hosts.txt -l mike expectSim.sh /tmp/expectSim.sh
./mikessh.sh "chmod a+x /tmp/updateSimics.sh"
./mikessh.sh "chmod a+x /tmp/expectSim.sh"
./mikessh.sh "/tmp/updateSimics.sh"

