ip route add default via 10.0.0.1 dev ens25

echo namserver 10.0.0.1 >/etc/resolv.conf
