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
chown -R mike:mike /home/mike/.ssh

# warning: the authoritative driver-server.py is at $RESIM_DIR/simics/bin/driver-server.py
# However this script grabs the copy from the workspace, which should be a sym link to the repo.
/usr/bin/simics-agent  --overwrite --download driver-server.py --to /tmp/

# Define the IP addresses we will use
ip addr add 10.0.0.140/24 dev ens25
ip link set ens11 up
#ethtool -K ens11 rx off tx off
#ethtool -K ens12 rx off tx off
#ethtool -K ens25 rx off tx off

# Start the driver server that receives commands from the host via drive-driver directives
systemctl start start_driver_server

ln -s /var/log/syslog /var/log/messages
chmod a+r /var/log/syslog
chmod a+r /var/log/messages
echo "just stuff" > /var/log/messages.0
chmod a+r /var/log/messages.0
/usr/bin/simics-agent --overwrite --upload /tmp/driver-ready.flag
