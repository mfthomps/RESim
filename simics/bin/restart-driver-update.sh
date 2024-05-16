sudo kill $(ps aux | grep '[d]river-server.py' | awk '{print $2}')
echo "did kill" >/tmp/kill.log
sudo mv /tmp/new_driver-server.py /tmp/driver-server.py
sudo nohup /tmp/driver-server.py restart &
echo "did restart" >/tmp/kill.log
