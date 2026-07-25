#!/bin/bash
# Assume port mapped to 2222 for VM
#
scp -P 2222 $RESIM_DIR/simics/simics-agent/simics-agent localhost:/tmp/
scp -P 2222 $RESIM_DIR/simics/driver_build/start_agent.sh localhost:/tmp/
scp -P 2222 $RESIM_DIR/simics/driver_build/start_agent.service localhost:/tmp/
scp -P 2222 $RESIM_DIR/simics/driver_build/start_driver_server.service localhost:/tmp/
scp -P 2222 $RESIM_DIR/simics/driver_build/install_agent.sh localhost:/tmp/
ssh -p 2222 localhost /tmp/install_agent.sh
