#!/bin/bash
# install packages needed by the slave
sudo apt-get update
sudo apt-get -y install openssh-server
sudo apt-get -y install nfs-common
sudo apt-get -y install python-dev
sudo apt-get -y install python-pip
sudo apt-get -y install python-support
sudo apt-get -y install default-jre
sudo apt-get -y install expect
sudo apt-get -y install mysql-client-core-5.5
sudo apt-get -y install python-mysqldb
sudo apt-get -y install libmysqlclient-dev
sudo pip install --index-url=http://linuxrepo/simple kazoo
