#!/bin/bash
#  use pscp to copy this to target, then run it via pssh
sudo adduser --disabled-password --gecos "" mike
sudo adduser mike sudo
sudo mkdir /home/mike/.ssh
sudo chown mike:mike /home/mike/.ssh
