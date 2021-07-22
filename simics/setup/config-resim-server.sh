#!/bin/bash
#
#  Configure a CGC blade server for use with RESim
#
echo "10.20.200.41 webproxy" >> /etc/hosts
#echo "Acquire::http::Proxy \"http://webproxy:3128\";" >> /etc/apt/apt.conf
mv /etc/apt/sources.list /etc/apt/sources.list.cgc
sources=/etc/apt/sources.list
cat > $sources <<- EOM
deb http://us.archive.ubuntu.com/ubuntu trusty universe
deb http://us.archive.ubuntu.com/ubuntu trusty main restricted
deb http://us.archive.ubuntu.com/ubuntu trusty-updates main restricted
EOM

mkdir /mnt/re_images
chmod a+rwx /mnt/re_images
echo "webproxy:/ubuntu_img /mnt/re_images nfs4 auto 0 0" >> /etc/fstab
mount -a
mkdir /eems_images
cd /eems_images
ln -s /mnt/re_images ubuntu_img

pip install /mnt/re_images/python_pkgs/python-magic-0.4.15.tar.gz

apt-get update
apt-get install -y xterm git
