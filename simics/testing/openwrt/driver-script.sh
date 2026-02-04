#
# Sample driver script.  The generic Ubuntu driver platform includes the simics agent.
# It will download this script from your workspace, and will then run the script.
# This allows you to easily change the content of the driver on each boot.
# 
# This instance of the script is intended to support the CADET01 example
# by uploading the client.py script to the driver.
#
#/usr/bin/simics-agent --executable --overwrite --download server --to /usr/bin
usermod -aG sudo mike
echo "mike ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
/usr/bin/simics-agent  --overwrite --download client.py --to /home/mike
mkdir -p /home/mike/.ssh
/usr/bin/simics-agent --executable --overwrite --download authorized_keys --to /home/mike/.ssh
chown -R mike:mike /home/mike/.ssh

# warning: the authoritative driver-server.py is at $RESIM_DIR/simics/bin/driver-server.py
# However this script grabs the copy from the workspace, which should be a sym link to the repo.
/usr/bin/simics-agent  --overwrite --download driver-server.py --to /tmp/

ip addr add 10.0.0.140/24 dev ens25
ip addr add 10.20.200.91/24 dev ens11
ip link set ens11 up

systemctl start start_driver_server

ln -s /var/log/syslog /var/log/messages
chmod a+r /var/log/syslog
chmod a+r /var/log/messages
echo "just stuff" > /var/log/messages.0
chmod a+r /var/log/messages.0
/usr/bin/simics-agent --overwrite --upload /tmp/driver-ready.flag
