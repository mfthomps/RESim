#!/bin/bash
cd /
tar -czf /tmp/rootfs.tar --exclude '/proc' --exclude '/sys' .
ps aux  > /tmp/ps.output
netstat -an > /tmp/netstat.output
ip addr > /tmp/ip_addr.output
dmesg > /tmp/dmsg.output
cd /tmp/
tar cf /tmp/artifacts.tar rootfs.tar ps.output netstat.output ip_addr.output dmsg.output
