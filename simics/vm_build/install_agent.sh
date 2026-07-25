#!/bin/bash
#
# To be run on the driver at the end of copy_agent.sh run from the host
#
sudo cp /tmp/simics-agent /usr/bin
sudo cp /tmp/start_agent.sh /usr/bin
sudo cp /tmp/start_agent.service /etc/systemd/system
sudo cp /tmp/start_driver_server.service /etc/systemd/system
sudo systemctl enable start_agent.service
