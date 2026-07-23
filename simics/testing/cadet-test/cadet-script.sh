#
# Set up a target to run the cadet01.  Assumes starting with 
# a provisioned system, e.g., via simics/vm_build
# with added sudo apt install libc6:i386 libstdc++6:i386
# to run 32 bit cadet program 
# 
#
# assume mike is a sudoer with nopasswd:all
# and has authorized keys
#
/usr/bin/simics-agent  --overwrite --download cadet.service --to /etc/systemd/system
/usr/bin/simics-agent  --overwrite --download cadet01 --to /usr/sbin/
systemctl enable cadet.service

# use netplan to define ip addr add 10.0.0.22/24 dev ens25
rm /etc/netplan/*
/usr/bin/simics-agent  --overwrite --download 80-my-init.yaml --to /etc/netplan/
#
/usr/sbin/netplan apply
/usr/bin/simics-agent --overwrite --upload /tmp/driver-ready.flag
systemctl disable start_agent
sync
poweroff
