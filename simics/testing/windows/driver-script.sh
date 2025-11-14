# See the RESim user guide for more details on driver-script.sh files.
#
# Sample driver script for windows.   When booted,
# the driver will download this script from your workspace, and will then run the script.
# This allows you to easily change the content of the driver on each boot.
# 
# This instance of the script is intended to support the initial Windows tests.
# It sets the IP addresses and not much else.  TBD, move functions of move2driver.sh
# into this script?
#
usermod -aG sudo mike
echo "mike ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
mkdir -p /home/mike/.ssh
/usr/bin/simics-agent --executable --overwrite --download authorized_keys --to /home/mike/.ssh
chown -R mike:mike /home/mike/.ssh

/usr/bin/simics-agent  --overwrite --download driver-server.py --to /tmp/

# NOTE: default driver image has 10.0.0.91 as IP, redefine that.

# The real network connection will be via ens25
ip addr add 10.0.0.140/24 dev ens25
# The connection to the windows box
ip addr add 10.10.0.91/24 dev ens12f0
ip link set ens12f0 up

systemctl start start_driver_server

# no longer sure if this junk is needed
ln -s /var/log/syslog /var/log/messages
chmod a+r /var/log/syslog
chmod a+r /var/log/messages
echo "just stuff" > /var/log/messages.0
chmod a+r /var/log/messages.0

# Let RESim know the driver is done initializing
/usr/bin/simics-agent --overwrite --upload /tmp/driver-ready.flag
