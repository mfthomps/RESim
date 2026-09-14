#
# Sample driver script.  The generic Ubuntu driver platform includes the simics agent.
# It will download this script from your workspace, and will then run the script.
# This allows you to easily change the content of the driver on each boot.
# 
#
# add the mike user and ssh keys for that user
usermod -aG sudo mike
echo "mike ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
mkdir -p /home/mike/.ssh
/usr/bin/simics-agent --executable --overwrite --download authorized_keys --to /home/mike/.ssh
#
#  Use this to move files from workspace to the target
#
#/usr/bin/simics-agent --executable --overwrite --download some_file --to /home/mike/
chown -R mike:mike /home/mike/.ssh

# warning: the authoritative driver-server.py is at $RESIM_DIR/simics/bin/driver-server.py
# However this script grabs the copy from the workspace, which should be a sym link to the repo.
/usr/bin/simics-agent  --overwrite --download driver-server.py --to /tmp/

# Define the driver IP addresses that we will use
ip addr add 10.0.0.140/24 dev ens25
ip link set ens25 up
#ip addr add 10.20.200.91/24 dev ens11f0
#ip link set ens11f0 up
#ethtool -K ens25 rx off tx off

/usr/bin/simics-agent --overwrite --upload /tmp/driver-ready.flag
