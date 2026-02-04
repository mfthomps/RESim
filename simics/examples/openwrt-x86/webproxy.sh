#
# Create a proxy through the driver to a target web server.
# It is assumed the driver can be reached via local port 4022 as user mike, with default RESim credentials.
# The target web server ip address (192.168.1.1) can be changed to match your target.
#
ssh -p 4022 -AfN -L 8081:192.168.1.1:80 -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -o "ServerAliveInterval 60" mike@localhost

