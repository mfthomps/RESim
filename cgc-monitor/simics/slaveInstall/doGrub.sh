#!/bin/bash
sudo cp grub /etc/default/grub
cd /etc/network
sudo sed -i.bak s/em1/eth0/g interfaces
sudo sed -i.bak s/em2/eth1/g interfaces
sudo update-grub
sudo reboot
