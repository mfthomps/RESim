#!/bin/sh


#
# *Might* be needed in some cases to force loading of the 'tuntap' driver.
#
#kextload /Library/Extensions/tun.kext


#SSH_KEY_DIR="/Users/mfthomps/.ssh/"
SSH_KEY_DIR="/home/mike/.ssh"
SSH_KEY="${SSH_KEY_DIR}/id_mfthomps_gfe"
REMOTE_TUN="0"
REMOTE_USER="mfthomps"
TUN_LOCAL_IP="192.168.3.2"
export TUN_REMOTE_IP="192.168.3.1"

#
# General settings. Do not change.
#
LOCAL_TUN="1"
TUN_NETMASK="255.255.255.252"
REMOTE_HOST=Gaijin
#export REMOTE_NETWORK="10.20.200.0/28"
export REMOTE_NETWORK="192.168.4.0/24"

#
# Establish SSH tunnel.
#
ssh -F /home/mike/.ssh/config -NTCf -p 22 -i ${SSH_KEY} -w ${LOCAL_TUN}:${REMOTE_TUN} ${REMOTE_USER}@${REMOTE_HOST}

#
# Configure local tunnel interface with a point-to-point network
ifconfig tun${LOCAL_TUN} ${TUN_LOCAL_IP} netmask ${TUN_NETMASK} pointopoint ${TUN_REMOTE_IP} mtu 800

#
# Add route to Thompson server management network.
#
route add -net "${REMOTE_NETWORK}" gw ${TUN_REMOTE_IP}


