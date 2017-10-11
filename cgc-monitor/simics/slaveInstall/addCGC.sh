#!/bin/bash
#  use pscp to copy this to target, then run it via pssh
sudo adduser --disabled-password --gecos "" cgc
sudo adduser cgc sudo
sudo mkdir /home/cgc/.ssh
sudo chown cgc:cgc /home/cgc/.ssh
