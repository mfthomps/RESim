#!/bin/bash
# set chrony to use 10.20.200.41
# external ntp do not sync with enclave
got=$(grep 10.20.200.41 /etc/chrony/chrony.conf)
if [ -z "$got" ];then
   echo "missing"
   sudo sed -i 's/^pool.*$/pool 10.20.200.41 iburst/' /etc/chrony/chrony.conf
   sudo /etc/init.d/chrony restart
fi
